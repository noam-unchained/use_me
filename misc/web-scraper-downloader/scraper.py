#!/usr/bin/env python3
"""
Web Scraper & File Downloader
================================
A Python tool that scrapes a target URL and:
  a. Extracts and displays all hyperlinks found on the page
  b. Downloads all images (jpg, png, etc.) from the page
  c. Downloads all linked PDF files from the page
  d. Saves all extracted links to a text file for reference

Usage:
    python scraper.py

Requirements:
    pip install -r requirements.txt
"""

from bs4 import BeautifulSoup
import requests
import os


# ─────────────────────────────────────────────
# STEP 1 — Fetch & Parse the Page
# ─────────────────────────────────────────────

# HTML Background:
# <a href="...">  — anchor tag; the href attribute holds the destination URL
# <img src="..."> — image tag; the src attribute holds the image URL
# We'll use both to extract links and downloadable files.

url = input("Enter the URL to scrape: ").strip()
response = requests.get(url)

# Parse the raw HTML into a navigable structure
soup = BeautifulSoup(response.text, "html.parser")


# ─────────────────────────────────────────────
# STEP 2a — Extract All Hyperlinks
# ─────────────────────────────────────────────

links = []

# Find all <a> tags that have an href attribute
for tag in soup.find_all('a', href=True):
    links.append(tag['href'])  # Extract just the URL from the href

print(f"\n[+] Found {len(links)} links on the page:\n")
for link in links:
    print(f"  {link}\n")


# ─────────────────────────────────────────────
# STEP 2b + 2c — Collect Downloadable Files
# ─────────────────────────────────────────────

files_to_download = []

# Images: <img src="..."> — covers jpg, png, gif, webp, etc.
for img in soup.find_all('img', src=True):
    files_to_download.append(img['src'])

# PDFs: <a href="...pdf"> — links ending in .pdf
for tag in soup.find_all('a', href=True):
    if tag['href'].lower().endswith('.pdf'):
        files_to_download.append(tag['href'])

print(f"[+] Found {len(files_to_download)} downloadable files (images + PDFs).\n")


# ─────────────────────────────────────────────
# STEP 3 — Save Files to Disk
# ─────────────────────────────────────────────

save_path = input("Enter the full path where files should be saved:\n> ").strip()
folder_name = input("Enter a name for the download folder:\n> ").strip()

folder_path = os.path.join(save_path, folder_name)

# exist_ok=True prevents an error if the folder already exists
os.makedirs(folder_path, exist_ok=True)

counter = 1  # Used to generate unique filenames for each downloaded file

for file_url in files_to_download:
    try:
        # .content returns the raw bytes of the HTTP response (needed for binary files)
        file_data = requests.get(file_url).content

        # Extract the file extension from the URL (e.g., "jpg" from "photo.jpg")
        extension = file_url.split('.')[-1]
        file_name = f"file_{counter}.{extension}"
        file_path = os.path.join(folder_path, file_name)

        # Write in binary mode ("wb") — works for both images and PDFs
        with open(file_path, "wb") as f:
            f.write(file_data)

        print(f"[+] Downloaded: {file_name}")
        counter += 1

    except Exception as e:
        # Log failures without crashing the whole script
        print(f"[-] Failed to download: {file_url} — {e}")


# ─────────────────────────────────────────────
# BONUS — Save All Links to a Text File
# ─────────────────────────────────────────────

# Saves a links.txt file in the same folder as the downloaded files
# Useful for offline reference or further recon
links_file_path = os.path.join(folder_path, 'links.txt')

with open(links_file_path, "w") as f:
    for link in links:
        f.write(f"{link}\n")

print(f"\n[+] All links saved to: {links_file_path}")
print(f"[+] Done. {counter - 1} file(s) downloaded to: {folder_path}")
