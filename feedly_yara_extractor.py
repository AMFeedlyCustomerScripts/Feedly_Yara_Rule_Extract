#!/usr/bin/env python3
"""
Feedly YARA Rule Extractor

Extracts YARA detection rules from Feedly Threat Intelligence streams
for use in threat hunting and endpoint detection.

Usage:
    # Using config file
    python feedly_yara_extractor.py -c config.yaml

    # Using environment variable and command line
    export FEEDLY_API_KEY="your_token_here"
    python feedly_yara_extractor.py --stream "feed/https://feedly.com/f/your-feed-id"

    # Output to file
    python feedly_yara_extractor.py --output rules.yara

    # Debug mode to inspect API structure
    python feedly_yara_extractor.py --debug

© 2025 Feedly, Inc. All rights reserved.

DISCLAIMERS. THE API SCRIPTS ARE PROVIDED "AS IS" FOR YOUR INTERNAL BUSINESS
USE ONLY. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE API SCRIPTS
IS WITH YOU. YOU AGREE THAT YOUR USE OF THE API SCRIPTS WILL BE AT YOUR SOLE
RISK. TO THE FULLEST EXTENT PERMITTED BY LAW, FEEDLY DISCLAIMS ALL WARRANTIES,
EXPRESS OR IMPLIED, IN CONNECTION WITH THE API SCRIPTS AND YOUR USE THEREOF,
INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. FEEDLY MAKES NO
WARRANTIES OR REPRESENTATIONS ABOUT THE ACCURACY OR COMPLETENESS OF THE API
SCRIPTS AND NO REPRESENTATIONS THAT THE API SCRIPTS ARE NOT OTHERWISE
ENCUMBERED BY ANY THIRD PARTY LICENSE, INCLUDING ANY OPEN-SOURCE LICENSE.
FEEDLY ASSUMES NO LIABILITY OR RESPONSIBILITY FOR ANY: (1) ERRORS, MISTAKES,
OR INACCURACIES; (2) PERSONAL INJURY OR PROPERTY DAMAGE, OF ANY NATURE
WHATSOEVER, RESULTING FROM YOUR USE OF THE API SCRIPTS; (3) ANY UNAUTHORIZED
ACCESS TO OR USE OF API SCRIPTS; (4) ANY INTERRUPTION OR CESSATION OF
TRANSMISSION TO OR FROM THE API SCRIPTS; (5) ANY BUGS, VIRUSES, TROJAN HORSES,
OR THE LIKE WHICH MAY BE TRANSMITTED TO OR THROUGH THE API SCRIPTS BY ANY
THIRD PARTY; OR (6) ANY ERRORS OR OMISSIONS IN THE API SCRIPTS OR FOR ANY LOSS
OR DAMAGE OF ANY KIND INCURRED AS A RESULT OF THE USE OF THE API SCRIPTS.

LIMITATION OF LIABILITY. IN NO EVENT SHALL FEEDLY BE LIABLE FOR ANY DAMAGES.
FURTHER, IN NO EVENT SHALL FEEDLY BE LIABLE FOR ANY CONSEQUENTIAL, INCIDENTAL
OR INDIRECT DAMAGES, INCLUDING, WITHOUT LIMITATION, ANY LOSS OF DATA, OR LOSS
OF PROFITS OR LOST SAVINGS, ARISING OUT OF USE OF OR INABILITY TO USE THE
LICENSED PRODUCT, EVEN IF FEEDLY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
DAMAGES, OR FOR ANY CLAIM BY ANY THIRD PARTY.

YOU ACKNOWLEDGE THAT YOU HAVE READ AND UNDERSTAND THESE TERMS AND AGREE TO BE
BOUND BY THEM. YOU FURTHER AGREE THAT THESE TERMS ARE THE COMPLETE AND
EXCLUSIVE STATEMENT OF THE AGREEMENT BETWEEN YOU AND FEEDLY FOR THE USE OF THE
API SCRIPTS, AND THESE TERMS SUPERSEDE ANY PRIOR AGREEMENT, ORAL OR WRITTEN,
AND ANY OTHER COMMUNICATIONS RELATING TO THE SUBJECT MATTER HEREOF.
"""

# =============================================================================
# IMPORTS
# =============================================================================

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library is required. Install with: pip install requests")
    sys.exit(1)

try:
    import yaml
except ImportError:
    yaml = None
    print("WARNING: PyYAML not installed. Config file loading disabled.")
    print("         Install with: pip install pyyaml")


# =============================================================================
# CONFIGURATION
# =============================================================================

# API Configuration
BASE_URL = "https://api.feedly.com"
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds
RATE_LIMIT_DELAY = 1  # seconds between API calls
REQUEST_TIMEOUT = 30  # seconds


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def load_api_key() -> str:
    """
    Load API key from environment variable or .env file.
    Priority: FEEDLY_API_KEY env var > .env file > fallback placeholder
    """
    # Check environment variable first
    api_key = os.environ.get("FEEDLY_API_KEY")
    if api_key:
        return api_key

    # Try to load from .env file in current directory or script directory
    env_locations = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
    ]

    for env_path in env_locations:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("FEEDLY_API_KEY=") and not line.startswith("#"):
                            key = line.split("=", 1)[1].strip()
                            # Remove quotes if present
                            if (key.startswith('"') and key.endswith('"')) or \
                               (key.startswith("'") and key.endswith("'")):
                                key = key[1:-1]
                            if key:
                                return key
            except Exception:
                pass

    return ""  # Return empty string if not found


def _request(
    session: requests.Session,
    method: str,
    endpoint: str,
    data=None,
    params=None,
    retries: int = MAX_RETRIES
) -> Optional[requests.Response]:
    """Make an API request with retry logic and rate limiting."""
    url = f"{BASE_URL}{endpoint}" if endpoint.startswith("/") else endpoint

    for attempt in range(retries):
        try:
            response = session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=REQUEST_TIMEOUT
            )

            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", RETRY_DELAY * (attempt + 1)))
                print(f"  Rate limited. Waiting {retry_after}s...")
                time.sleep(retry_after)
                continue

            # Handle server errors with retry
            if response.status_code >= 500:
                if attempt < retries - 1:
                    wait_time = RETRY_DELAY * (attempt + 1)
                    print(f"  Server error {response.status_code}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    continue

            return response

        except requests.exceptions.RequestException as e:
            if attempt < retries - 1:
                wait_time = RETRY_DELAY * (attempt + 1)
                print(f"  Connection error: {e}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue
            raise

    return None


# =============================================================================
# API FUNCTIONS
# =============================================================================

def get_stream_contents(
    session: requests.Session,
    stream_id: str,
    count: int = 100,
    newer_than: Optional[int] = None,
    continuation: Optional[str] = None
) -> Dict[str, Any]:
    """Fetch articles from a Feedly stream."""
    params = {
        "streamId": stream_id,
        "count": min(count, 100)
    }

    if newer_than:
        params["newerThan"] = newer_than
    if continuation:
        params["continuation"] = continuation

    response = _request(
        session=session,
        method="GET",
        endpoint="/v3/streams/contents",
        params=params
    )

    if response is None:
        return {"items": []}

    response.raise_for_status()
    return response.json()


def get_article_details(session: requests.Session, article_id: str) -> Dict[str, Any]:
    """Fetch full article details by ID."""
    response = _request(
        session=session,
        method="POST",
        endpoint="/v3/entries/.mget",
        data=[article_id]
    )

    if response is None:
        return {}

    response.raise_for_status()
    results = response.json()
    return results[0] if results else {}


# =============================================================================
# YARA EXTRACTION FUNCTIONS
# =============================================================================

def extract_yara_from_text(text: str) -> List[str]:
    """Extract YARA rules from raw text using regex."""
    rules = []
    comprehensive_pattern = r'rule\s+(\w+)(?:\s*:\s*[\w\s]+)?\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
    matches = re.findall(comprehensive_pattern, text, re.DOTALL | re.IGNORECASE)

    for match in matches:
        rule_name = match[0]
        rule_body = match[1]
        full_rule = f"rule {rule_name} {{{rule_body}}}"
        if 'strings:' in rule_body.lower() or 'condition:' in rule_body.lower():
            rules.append(full_rule.strip())

    return rules


def find_yara_fields(obj: Any, path: str = "") -> List[tuple]:
    """Recursively find any fields related to YARA or detection rules."""
    findings = []

    if isinstance(obj, dict):
        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else key
            key_lower = key.lower()

            # Check if this key is related to YARA/detection
            if any(term in key_lower for term in ['yara', 'detection', 'rule', 'sigma', 'snort']):
                findings.append((current_path, type(value).__name__, str(value)[:200]))

            # Recurse
            findings.extend(find_yara_fields(value, current_path))

    elif isinstance(obj, list):
        for i, item in enumerate(obj[:3]):  # Only check first 3 items
            findings.extend(find_yara_fields(item, f"{path}[{i}]"))

    return findings


def extract_yara_from_article(
    session: requests.Session,
    article: Dict[str, Any],
    debug: bool = False
) -> List[Dict[str, Any]]:
    """Extract YARA rules from a Feedly article using multiple methods."""
    yara_rules = []
    article_id = article.get("id", "unknown")
    article_title = article.get("title", "Unknown Title")
    article_url = article.get("canonicalUrl") or article.get("originId", "")
    published = article.get("published", 0)

    if debug:
        print(f"\n  [DEBUG] Top-level keys: {list(article.keys())}")
        yara_findings = find_yara_fields(article)
        if yara_findings:
            print("  [DEBUG] YARA-related fields found:")
            for path, type_name, preview in yara_findings:
                print(f"    - {path} ({type_name}): {preview}...")

    # Method 1: Check detectionRules.yara (array of rules)
    detection_rules = article.get("detectionRules", {})
    if debug and detection_rules:
        dr_keys = list(detection_rules.keys()) if isinstance(detection_rules, dict) else type(detection_rules)
        print(f"  [DEBUG] detectionRules keys: {dr_keys}")

    yara_data = detection_rules.get("yara", []) if isinstance(detection_rules, dict) else []

    if yara_data:
        print(f"  Found {len(yara_data)} YARA rules via detectionRules.yara")
        for rule in yara_data:
            rule_content = rule.get("content", "") if isinstance(rule, dict) else str(rule)
            if rule_content:
                yara_rules.append({
                    "content": rule_content,
                    "source_article_id": article_id,
                    "source_article_title": article_title,
                    "source_url": article_url,
                    "published_timestamp": published,
                    "extraction_method": "detectionRules.yara"
                })

    # Method 2: Check detectionRules.yaraExport.url
    yara_export = detection_rules.get("yaraExport", {}) if isinstance(detection_rules, dict) else {}
    export_url = yara_export.get("url") if isinstance(yara_export, dict) else None

    if export_url:
        print(f"  Found YARA export URL: {export_url[:60]}...")
        try:
            yara_response = _request(session, "GET", export_url)
            if yara_response and yara_response.status_code == 200:
                yara_rules.append({
                    "content": yara_response.text,
                    "source_article_id": article_id,
                    "source_article_title": article_title,
                    "source_url": article_url,
                    "published_timestamp": published,
                    "extraction_method": "yaraExport.url"
                })
        except requests.exceptions.RequestException as e:
            print(f"  WARNING: Failed to fetch YARA export URL: {e}")

    # Method 3: Check indicatorsOfCompromise.yaraRules.url
    ioc_data = article.get("indicatorsOfCompromise", {})
    yara_rules_obj = ioc_data.get("yaraRules", {}) if isinstance(ioc_data, dict) else {}
    if isinstance(yara_rules_obj, dict) and yara_rules_obj.get("url"):
        yara_url = yara_rules_obj["url"]
        yara_count = yara_rules_obj.get("count", "?")
        print(f"  Found indicatorsOfCompromise.yaraRules.url with {yara_count} rules")
        try:
            yara_response = _request(session, "GET", yara_url)
            if yara_response and yara_response.status_code == 200:
                yara_rules.append({
                    "content": yara_response.text,
                    "source_article_id": article_id,
                    "source_article_title": article_title,
                    "source_url": article_url,
                    "published_timestamp": published,
                    "extraction_method": "indicatorsOfCompromise.yaraRules.url"
                })
        except requests.exceptions.RequestException as e:
            print(f"  WARNING: Failed to fetch yaraRules.url: {e}")

    # Method 4: Check linked articles for yaraRules
    linked_articles = article.get("linked", [])
    for i, linked in enumerate(linked_articles):
        if isinstance(linked, dict):
            linked_ioc = linked.get("indicatorsOfCompromise", {})
            linked_yara = linked_ioc.get("yaraRules", {}) if isinstance(linked_ioc, dict) else {}
            if isinstance(linked_yara, dict) and linked_yara.get("url"):
                yara_url = linked_yara["url"]
                yara_count = linked_yara.get("count", "?")
                print(f"  Found linked[{i}].indicatorsOfCompromise.yaraRules.url with {yara_count} rules")
                try:
                    yara_response = _request(session, "GET", yara_url)
                    if yara_response and yara_response.status_code == 200:
                        yara_rules.append({
                            "content": yara_response.text,
                            "source_article_id": article_id,
                            "source_article_title": article_title,
                            "source_url": article_url,
                            "published_timestamp": published,
                            "extraction_method": "linked.indicatorsOfCompromise.yaraRules.url"
                        })
                except requests.exceptions.RequestException as e:
                    print(f"  WARNING: Failed to fetch linked yaraRules.url: {e}")

    # Method 5: Check entities for YARA download links
    entities = article.get("entities", [])
    for entity in entities:
        if isinstance(entity, dict):
            entity_type = entity.get("type", "")
            if "yara" in entity_type.lower() or "detection" in entity_type.lower():
                if debug:
                    print(f"  [DEBUG] Found entity: {entity}")

    # Method 6: Regex extraction from content (fallback)
    content = article.get("content", {}).get("content", "") or \
              article.get("summary", {}).get("content", "") or \
              article.get("fullContent", "")

    if content:
        extracted = extract_yara_from_text(content)
        if extracted:
            print(f"  Extracted {len(extracted)} YARA rules via regex")
            for rule_content in extracted:
                yara_rules.append({
                    "content": rule_content,
                    "source_article_id": article_id,
                    "source_article_title": article_title,
                    "source_url": article_url,
                    "published_timestamp": published,
                    "extraction_method": "regex_extraction"
                })

    return yara_rules


# =============================================================================
# MAIN EXTRACTION FUNCTION
# =============================================================================

def fetch_yara_rules(
    api_token: str,
    stream_ids: List[str],
    since_hours: int = 24,
    max_articles: int = 500,
    debug: bool = False,
    fetch_full: bool = False
) -> List[Dict[str, Any]]:
    """Fetch all YARA rules from configured streams."""

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json"
    })

    print("\n" + "="*60)
    print("Verifying Feedly API connection...")
    print("="*60)

    try:
        profile_resp = _request(session, "GET", "/v3/profile")
        if profile_resp is None:
            print("ERROR: Failed to connect to Feedly API")
            return []

        if profile_resp.status_code == 200:
            profile = profile_resp.json()
            print(f"Connected as: {profile.get('email', 'unknown')}")
        elif profile_resp.status_code == 401:
            print("ERROR: Invalid API token (401 Unauthorized)")
            return []
        else:
            print(f"WARNING: Profile check returned {profile_resp.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Connection error: {e}")
        return []

    all_rules = []
    seen_hashes = set()
    newer_than = int((datetime.now(timezone.utc) - timedelta(hours=since_hours)).timestamp() * 1000)

    for stream_id in stream_ids:
        print("\n" + "="*60)
        print(f"Processing stream: {stream_id[:60]}...")
        print("="*60)

        articles_processed = 0
        articles_with_yara = 0
        continuation = None

        while articles_processed < max_articles:
            try:
                data = get_stream_contents(
                    session=session,
                    stream_id=stream_id,
                    count=100,
                    newer_than=newer_than,
                    continuation=continuation
                )
            except requests.exceptions.HTTPError as e:
                if hasattr(e, 'response') and e.response.status_code == 404:
                    print(f"ERROR: Stream not found: {stream_id}")
                else:
                    print(f"ERROR: Error fetching stream: {e}")
                break
            except requests.exceptions.RequestException as e:
                print(f"ERROR: Connection error: {e}")
                break

            items = data.get("items", [])
            if not items:
                print("  No more articles in this time range")
                break

            if debug and articles_processed == 0:
                print(f"\n[DEBUG] First article raw structure:")
                print(f"  Keys: {list(items[0].keys())}")
                yara_findings = find_yara_fields(items[0])
                if yara_findings:
                    print("  YARA-related fields:")
                    for path, type_name, preview in yara_findings:
                        print(f"    - {path} ({type_name}): {preview}")
                else:
                    print("  No YARA-related fields found in stream response")
                    print("  Will try fetching full article details...")
                    fetch_full = True

            for article in items:
                title = article.get("title", "No title")[:50]
                article_id = article.get("id")

                # Check for any indication of YARA content
                has_detection_rules = bool(article.get("detectionRules"))

                # Check indicatorsOfCompromise.yaraRules
                ioc_data = article.get("indicatorsOfCompromise", {})
                ioc_yara = ioc_data.get("yaraRules", {}) if isinstance(ioc_data, dict) else {}
                has_yara_rules = isinstance(ioc_yara, dict) and bool(ioc_yara.get("url"))

                # Check linked articles for yaraRules
                has_linked_yara = False
                for linked in article.get("linked", []):
                    if isinstance(linked, dict):
                        linked_ioc = linked.get("indicatorsOfCompromise", {})
                        linked_yara = linked_ioc.get("yaraRules", {}) if isinstance(linked_ioc, dict) else {}
                        if isinstance(linked_yara, dict) and linked_yara.get("url"):
                            has_linked_yara = True
                            break

                # Also check commonTopics for YARA tag
                common_topics = article.get("commonTopics", [])
                has_yara_topic = any(
                    t.get("id") == "nlp/f/topic/7001" or "yara" in t.get("label", "").lower()
                    for t in common_topics if isinstance(t, dict)
                )

                should_process = has_detection_rules or has_yara_rules or has_linked_yara or has_yara_topic

                if debug:
                    print(f"\n[Article] {title}...")
                    print(f"  has_detection_rules: {has_detection_rules}")
                    print(f"  has_yara_rules: {has_yara_rules}")
                    print(f"  has_linked_yara: {has_linked_yara}")
                    print(f"  has_yara_topic: {has_yara_topic}")

                if should_process or debug:
                    # Try fetching full article if stream doesn't have detection data
                    if fetch_full and not has_detection_rules and article_id:
                        if debug:
                            print("  Fetching full article details...")
                        try:
                            full_article = get_article_details(session, article_id)
                            if full_article:
                                article = full_article
                                has_detection_rules = bool(article.get("detectionRules"))
                                if debug:
                                    print(f"  Full article has detectionRules: {has_detection_rules}")
                                    if article.get("detectionRules"):
                                        print(f"  detectionRules keys: {list(article['detectionRules'].keys())}")
                        except Exception as e:
                            if debug:
                                print(f"  Failed to fetch full article: {e}")

                    if has_detection_rules or has_yara_rules or has_linked_yara or debug:
                        print(f"\nProcessing: {title}...")
                        rules = extract_yara_from_article(session, article, debug=debug)

                        if rules:
                            articles_with_yara += 1
                            for rule in rules:
                                rule_hash = hashlib.md5(rule["content"].encode()).hexdigest()
                                if rule_hash not in seen_hashes:
                                    seen_hashes.add(rule_hash)
                                    rule["content_hash"] = rule_hash
                                    all_rules.append(rule)

                # Rate limiting between articles
                time.sleep(RATE_LIMIT_DELAY)

            articles_processed += len(items)
            continuation = data.get("continuation")

            if not continuation:
                break

            # In debug mode, only process first batch
            if debug:
                print("\n[DEBUG] Stopping after first batch in debug mode")
                break

        print(f"\n  Processed {articles_processed} articles")
        print(f"  Found {articles_with_yara} articles with YARA rules")

    return all_rules


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Extract YARA rules from Feedly Threat Intelligence streams"
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )
    parser.add_argument(
        "--token",
        help="Feedly API token (overrides config file and env var)"
    )
    parser.add_argument(
        "--stream",
        action="append",
        dest="streams",
        help="Stream ID to fetch from (can be specified multiple times)"
    )
    parser.add_argument(
        "--since-hours",
        type=int,
        default=24,
        help="Fetch articles from the last N hours (default: 24)"
    )
    parser.add_argument(
        "--max-articles",
        type=int,
        default=500,
        help="Maximum articles to process (default: 500)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for YARA rules (default: print to console)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON with metadata"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show raw API structure for debugging"
    )
    parser.add_argument(
        "--fetch-full",
        action="store_true",
        help="Fetch full article details (slower but more complete)"
    )

    args = parser.parse_args()

    # Get API token (priority: CLI arg > env var > config file)
    api_token = args.token
    stream_ids = args.streams or []

    # Try loading from environment if not provided
    if not api_token:
        api_token = load_api_key()

    # Try loading from config file
    if (not api_token or not stream_ids) and yaml:
        config_path = args.config
        if os.path.exists(config_path):
            print(f"Loading configuration from {config_path}...")
            try:
                with open(config_path) as f:
                    config = yaml.safe_load(f)
                if not api_token:
                    api_token = config.get("feedly", {}).get("api_token")
                if not stream_ids:
                    stream_ids = config.get("feedly", {}).get("stream_ids", [])
            except Exception as e:
                print(f"WARNING: Failed to load config file: {e}")

    # Validate required parameters
    if not api_token:
        print("\nERROR: Feedly API token required")
        print("\nProvide token via one of these methods:")
        print("  1. Command line: --token YOUR_TOKEN")
        print("  2. Environment variable: export FEEDLY_API_KEY=YOUR_TOKEN")
        print("  3. Config file: api_token in config.yaml")
        print("  4. .env file: FEEDLY_API_KEY=YOUR_TOKEN")
        sys.exit(1)

    if not stream_ids:
        print("\nERROR: At least one stream ID required")
        print("\nProvide stream IDs via:")
        print("  1. Command line: --stream STREAM_ID")
        print("  2. Config file: stream_ids in config.yaml")
        sys.exit(1)

    # Fetch YARA rules
    rules = fetch_yara_rules(
        api_token=api_token,
        stream_ids=stream_ids,
        since_hours=args.since_hours,
        max_articles=args.max_articles,
        debug=args.debug,
        fetch_full=args.fetch_full
    )

    # Display results
    print("\n" + "="*60)
    print("RESULTS")
    print("="*60)
    print(f"Total unique YARA rules found: {len(rules)}")

    if not rules:
        print("\nNo YARA rules found.")
        print("\nTry:")
        print("  - Increasing --since-hours to look further back")
        print("  - Running with --debug to see API structure")
        print("  - Running with --fetch-full to get complete article data")
        return

    # Group by extraction method
    by_method = {}
    for rule in rules:
        method = rule.get("extraction_method", "unknown")
        by_method[method] = by_method.get(method, 0) + 1

    print("\nExtraction methods:")
    for method, count in by_method.items():
        print(f"  - {method}: {count} rules")

    # Format output
    if args.json:
        output_data = {
            "extracted_at": datetime.now(timezone.utc).isoformat(),
            "total_rules": len(rules),
            "rules": rules
        }
        output_text = json.dumps(output_data, indent=2)
    else:
        output_lines = [
            "# YARA Rules extracted from Feedly Threat Intelligence",
            f"# Extracted: {datetime.now(timezone.utc).isoformat()}",
            f"# Total rules: {len(rules)}",
            ""
        ]
        for rule in rules:
            output_lines.append(f"// Source: {rule.get('source_url', 'unknown')}")
            output_lines.append(f"// Title: {rule.get('source_article_title', 'unknown')}")
            output_lines.append(f"// Method: {rule.get('extraction_method', 'unknown')}")
            output_lines.append(rule["content"])
            output_lines.append("")
        output_text = "\n".join(output_lines)

    # Output to file or console
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_text)
        print(f"\nRules written to: {args.output}")
    else:
        print("\n" + "-"*60)
        print("YARA RULES PREVIEW:")
        print("-"*60)
        for i, rule in enumerate(rules[:3]):
            print(f"\n--- Rule {i+1} ---")
            print(f"Source: {rule.get('source_article_title', 'unknown')[:60]}")
            print(f"Method: {rule.get('extraction_method')}")
            content = rule["content"]
            if len(content) > 500:
                print(f"Content: {content[:500]}...")
            else:
                print(f"Content: {content}")

        if len(rules) > 3:
            print(f"\n... and {len(rules) - 3} more rules")
            print("\nUse --output rules.yara to save all rules to a file")


if __name__ == "__main__":
    main()
