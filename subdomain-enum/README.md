# 🔍 Subdomain Enumeration Tool

A Bash script that automates subdomain discovery by running three tools in sequence — **Subfinder**, **Assetfinder**, and **Sublist3r** — then merges and deduplicates all results into a single clean file.

> ⚠️ **For educational and authorized use only.** Only run against domains you own or have explicit permission to test.

---

## 🚀 What It Does

1. **Normalizes the input** — strips protocol and path, works with both `example.com` and `https://example.com/anything`
2. **Checks tool availability** — warns if a tool is missing instead of crashing
3. **Runs three enumeration tools** — each targeting different data sources
4. **Shows per-tool count** — so you know how many subdomains each tool found
5. **Merges & deduplicates** — combines all results with `sort -u` into one clean file
6. **Prints a summary** — total unique subdomains found and output path

---

## 🛠️ Requirements

Install the required tools:

```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Assetfinder
go install github.com/tomnomnom/assetfinder@latest

# Sublist3r
pip install sublist3r
```

---

## ▶️ Usage

```bash
chmod +x subdomain_enum.sh
./subdomain_enum.sh example.com
# or
./subdomain_enum.sh https://example.com
```

**Example output:**
```
═══════════════════════════════════════════
   Subdomain Enumeration — example.com
═══════════════════════════════════════════

[+] Running Subfinder...
    └── Found 43 subdomains
[+] Running Assetfinder...
    └── Found 31 subdomains
[+] Running Sublist3r...
    └── Found 27 subdomains

[*] Merging and deduplicating results...

═══════════════════════════════════════════
   Done!
   Total unique subdomains: 58
   Results saved to: example.com/recon/subs.txt
═══════════════════════════════════════════
```

---

## 📁 Output Structure

```
example.com/
└── recon/
    ├── subfinder.txt      # Raw results from Subfinder
    ├── assetfinder.txt    # Raw results from Assetfinder
    ├── sublist3r.txt      # Raw results from Sublist3r
    └── subs.txt           # Final merged & deduplicated list
```

---

## 🔮 Possible Extensions

- [ ] Add `httpx` to probe which subdomains are alive
- [ ] Add `--threads` flag for parallel tool execution
- [ ] Pipe live subdomains into `nmap` for port scanning
- [ ] Send results to a Slack/Discord webhook

---

## ⚠️ Disclaimer

This tool is for **educational use** in authorized penetration testing and bug bounty environments only.

---

## 📄 License

MIT
