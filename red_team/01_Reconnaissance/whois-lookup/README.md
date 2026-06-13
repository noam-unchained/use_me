# whois-lookup

WHOIS query tool. Pulls registration data for one or more domains.

## Usage

```bash
python3 whois_lookup.py example.com
python3 whois_lookup.py example.com target.org -o results.json
```

## Output

Registrar, creation/expiration dates, name servers, registrant email, country, DNSSEC status.

## Requirements

```bash
pip install -r requirements.txt
```
