#!/bin/bash
# ─────────────────────────────────────────────────────────────
# subdomain_enum.sh — Automated Subdomain Enumeration Tool
#
# Runs three subdomain discovery tools in parallel against a
# target domain, merges the results, deduplicates, and saves
# a clean output file.
#
# Tools required: subfinder, assetfinder, sublist3r
#
# Usage:
#   ./subdomain_enum.sh <domain.com>
#   ./subdomain_enum.sh https://example.com   (full URL also works)
# ─────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────
# Input Validation & URL Normalization
# ─────────────────────────────────────────────

# Strip protocol and path from URL — keeps only the domain
# e.g. https://example.com/page → example.com
dn=$(echo "$1" | sed -e 's|^[^/]*//||' -e 's|/.*$||')

if [ -z "$dn" ]; then
    echo "Usage: ./subdomain_enum.sh <domain.com>"
    echo "       ./subdomain_enum.sh https://example.com"
    exit 1
fi

# ─────────────────────────────────────────────
# Tool Availability Check
# ─────────────────────────────────────────────

# Warn the user if any tool is missing — won't abort, just skips
for tool in subfinder assetfinder sublist3r; do
    if ! command -v "$tool" &>/dev/null; then
        echo "[!] Warning: '$tool' not found — skipping."
    fi
done

# ─────────────────────────────────────────────
# Setup Output Directory
# ─────────────────────────────────────────────

output_dir="$dn/recon"
mkdir -p "$output_dir"

echo ""
echo "═══════════════════════════════════════════"
echo "   Subdomain Enumeration — $dn"
echo "═══════════════════════════════════════════"
echo ""

# ─────────────────────────────────────────────
# Step 1 — Run Enumeration Tools
# ─────────────────────────────────────────────

# Subfinder: fast passive subdomain discovery
if command -v subfinder &>/dev/null; then
    echo "[+] Running Subfinder..."
    subfinder -d "$dn" -silent -o "$output_dir/subfinder.txt" 2>/dev/null
    count=$(wc -l < "$output_dir/subfinder.txt" 2>/dev/null || echo 0)
    echo "    └── Found $count subdomains"
fi

# Assetfinder: certificate transparency + various APIs
if command -v assetfinder &>/dev/null; then
    echo "[+] Running Assetfinder..."
    assetfinder --subs-only "$dn" > "$output_dir/assetfinder.txt" 2>/dev/null
    count=$(wc -l < "$output_dir/assetfinder.txt" 2>/dev/null || echo 0)
    echo "    └── Found $count subdomains"
fi

# Sublist3r: scrapes search engines and DNS datasets
if command -v sublist3r &>/dev/null; then
    echo "[+] Running Sublist3r..."
    sublist3r -d "$dn" -o "$output_dir/sublist3r.txt" 2>/dev/null
    count=$(wc -l < "$output_dir/sublist3r.txt" 2>/dev/null || echo 0)
    echo "    └── Found $count subdomains"
fi

# ─────────────────────────────────────────────
# Step 2 — Merge & Deduplicate Results
# ─────────────────────────────────────────────

echo ""
echo "[*] Merging and deduplicating results..."

merged="$output_dir/all_raw.txt"
final="$output_dir/subs.txt"

# Only append files that exist and are non-empty (-s flag)
> "$merged"  # Create/clear the temp merge file
[ -s "$output_dir/subfinder.txt" ]   && cat "$output_dir/subfinder.txt"   >> "$merged"
[ -s "$output_dir/assetfinder.txt" ] && cat "$output_dir/assetfinder.txt" >> "$merged"
[ -s "$output_dir/sublist3r.txt" ]   && cat "$output_dir/sublist3r.txt"   >> "$merged"

# sort -u removes duplicates and sorts alphabetically
sort -u "$merged" > "$final"

# Clean up the temporary merge file
rm -f "$merged"

# ─────────────────────────────────────────────
# Step 3 — Summary
# ─────────────────────────────────────────────

total=$(wc -l < "$final")

echo ""
echo "═══════════════════════════════════════════"
echo "   Done!"
echo "   Total unique subdomains: $total"
echo "   Results saved to: $final"
echo "═══════════════════════════════════════════"
echo ""
