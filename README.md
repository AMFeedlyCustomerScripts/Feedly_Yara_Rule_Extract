# Feedly YARA Rule Extractor

Extract YARA detection rules from Feedly Threat Intelligence streams for use in threat hunting and endpoint detection.

## Overview

This tool connects to Feedly's Threat Intelligence API to automatically extract YARA rules from:
- Detection Rules AI Feeds
- Threat Intelligence articles
- Linked research and reports

The extracted rules can be used with:
- Velociraptor for endpoint hunting
- YARA scanners for file analysis
- SIEM systems for detection
- Other threat hunting platforms

## Requirements

- Python 3.8+
- Feedly API token (from Feedly TI subscription)
- One or more Feedly stream IDs containing threat intelligence

## Installation

1. Clone or download this repository

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure your credentials (choose one method):

   **Option A: Environment variable**
   ```bash
   export FEEDLY_API_KEY="your_feedly_api_token"
   ```

   **Option B: .env file**
   ```bash
   echo 'FEEDLY_API_KEY="your_feedly_api_token"' > .env
   ```

   **Option C: Config file**
   ```bash
   cp config.yaml.template config.yaml
   # Edit config.yaml with your credentials
   ```

## Usage

### Basic Usage

```bash
# Using config file
python feedly_yara_extractor.py

# Using environment variable and command line
export FEEDLY_API_KEY="your_token"
python feedly_yara_extractor.py --stream "feed/https://feedly.com/f/your-feed-id"

# Output to file
python feedly_yara_extractor.py --output rules.yara
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-c, --config` | Path to config file (default: config.yaml) |
| `--token` | Feedly API token (overrides config/env) |
| `--stream` | Stream ID (can be used multiple times) |
| `--since-hours` | Look back N hours (default: 24) |
| `--max-articles` | Max articles to process (default: 500) |
| `-o, --output` | Output file path |
| `--json` | Output as JSON with metadata |
| `--debug` | Show raw API structure |
| `--fetch-full` | Fetch complete article details |

### Examples

```bash
# Extract rules from last 72 hours
python feedly_yara_extractor.py --since-hours 72

# Extract from multiple streams
python feedly_yara_extractor.py \
  --stream "feed/https://feedly.com/f/feed1" \
  --stream "feed/https://feedly.com/f/feed2"

# Output as JSON for programmatic use
python feedly_yara_extractor.py --output rules.json --json

# Debug mode to inspect API response
python feedly_yara_extractor.py --debug
```

## Configuration File

Create `config.yaml` from the template:

```yaml
feedly:
  api_token: "your_feedly_api_token"
  stream_ids:
    - "feed/https://feedly.com/f/your-feed-id"
```

## YARA Extraction Methods

The tool uses multiple methods to extract YARA rules:

1. **detectionRules.yara** - Direct YARA rules in article data
2. **yaraExport.url** - Downloadable YARA rule files
3. **indicatorsOfCompromise.yaraRules.url** - IOC-linked YARA rules
4. **linked articles** - Rules from referenced articles
5. **regex extraction** - Fallback pattern matching in content

## Output Formats

### YARA Format (default)
```
# YARA Rules extracted from Feedly Threat Intelligence
# Extracted: 2025-01-20T12:00:00Z
# Total rules: 5

// Source: https://example.com/threat-report
// Title: APT Analysis Report
// Method: indicatorsOfCompromise.yaraRules.url
rule APT_Malware_Sample {
    strings:
        $s1 = "malicious_string"
    condition:
        $s1
}
```

### JSON Format (--json)
```json
{
  "extracted_at": "2025-01-20T12:00:00Z",
  "total_rules": 5,
  "rules": [
    {
      "content": "rule APT_Malware...",
      "source_article_id": "...",
      "source_article_title": "APT Analysis Report",
      "source_url": "https://example.com/threat-report",
      "extraction_method": "indicatorsOfCompromise.yaraRules.url",
      "content_hash": "abc123..."
    }
  ]
}
```

## Troubleshooting

### No YARA rules found

1. Increase the time range: `--since-hours 168` (1 week)
2. Run with debug mode: `--debug`
3. Try fetching full articles: `--fetch-full`
4. Verify your stream contains Detection Rules content

### Authentication errors

- Verify your API token is valid
- Check token hasn't expired
- Ensure you have Feedly TI subscription access

### Rate limiting

The tool includes automatic retry logic with exponential backoff. If you hit rate limits frequently, the tool will pause and retry automatically.

## Security Notes

- **Never commit credentials** - config.yaml and .env are in .gitignore
- Store API tokens securely
- Use environment variables in CI/CD pipelines
- Rotate API tokens periodically

## License

© 2025 Feedly, Inc. All rights reserved.

This script is provided "AS IS" for internal business use only. See the script header for full disclaimer and terms of use.
