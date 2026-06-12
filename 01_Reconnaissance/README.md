# Reconnaissance

The first phase. No active contact with the target — everything here is passive collection.

The goal is to build a picture of the target before touching anything: who works there, what domains they own, what infrastructure is exposed, what emails are public. The more you know going in, the less noise you make later.

This phase feeds directly into scanning and exploitation — subdomains become targets, emails become phishing candidates, WHOIS data reveals registrar info and org structure.

## Tools

| Tool | Purpose |
|------|---------|
| [the-harvester](the-harvester/) | Collect emails and subdomains from search engines and public sources |
| [whois-lookup](whois-lookup/) | Pull registration data for domains |
| [email-enum](email-enum/) | Enumerate valid email addresses for a domain |
| [subdomain-enum](subdomain-enum/) | Discover subdomains via DNS brute-force |
