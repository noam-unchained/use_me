# the-harvester

Passive OSINT tool for collecting emails and subdomains from public sources.

## Sources

- Google / Bing search (email scraping)
- crt.sh (certificate transparency logs)
- HackerTarget API (subdomain lookup)

## Usage

```bash
python3 the_harvester.py -d example.com
python3 the_harvester.py -d example.com -s google,crt
python3 the_harvester.py -d example.com -o results.txt
```

## Options

| Flag | Description |
|------|-------------|
| `-d` | Target domain |
| `-s` | Sources to use (default: all) |
| `-o` | Output file |

## Requirements

```bash
pip install -r requirements.txt
```
