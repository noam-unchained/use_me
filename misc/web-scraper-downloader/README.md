# ️ Web Scraper & File Downloader

A Python tool that scrapes a target webpage and automatically extracts all links, downloads images, and saves PDF files — with a clean summary saved to disk.

---

## What It Does

### Step 1 — Link Extraction
Parses the page HTML using **BeautifulSoup** and extracts every `<a href="...">` tag. 
Prints all discovered URLs to the terminal for quick inspection.

### Step 2 — File Collection
Collects two types of downloadable content:
- **Images** — found via `<img src="...">` tags (jpg, png, gif, webp, etc.)
- **PDFs** — found via `<a href="...pdf">` links

### Step 3 — Download & Save
Downloads each file as raw bytes and saves it locally with an auto-numbered filename (`file_1.jpg`, `file_2.pdf`, ...). 
Creates the destination folder automatically if it doesn't exist.

### Bonus — Links Log
Saves all extracted links to a `links.txt` file in the same download folder for offline reference.

---

## ️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/web-scraper-downloader.git
cd web-scraper-downloader
pip install -r requirements.txt
```

---

## ▶️ Usage

```bash
python scraper.py
```

**Example flow:**
```
Enter the URL to scrape: https://example.com

[+] Found 12 links on the page:
https://example.com/about
https://example.com/report.pdf
...

[+] Found 5 downloadable files (images + PDFs).

Enter the full path where files should be saved:
> /Users/noam/Downloads
Enter a name for the download folder:
> example_scrape

[+] Downloaded: file_1.jpg
[+] Downloaded: file_2.png
[+] Downloaded: file_3.pdf
[+] All links saved to: /Users/noam/Downloads/example_scrape/links.txt
[+] Done. 3 file(s) downloaded to: /Users/noam/Downloads/example_scrape
```

---

## Tech Stack

| Library | Purpose |
|---|---|
| `requests` | HTTP GET requests + raw byte content for file downloads |
| `BeautifulSoup` | HTML parsing — tag and attribute extraction |
| `os` | File system operations — folder creation, path handling |

---

## Key Concepts

**Why `.content` instead of `.text` for downloads?** 
`.text` returns a decoded string — fine for HTML but it corrupts binary files like images and PDFs. 
`.content` returns raw bytes, which is what you need when writing files with `"wb"` (write binary).

**HTML structure this tool targets:**
```html
<!-- Links -->
<a href="https://example.com/page">Click here</a>

<!-- Images -->
<img src="https://example.com/photo.jpg">

<!-- PDFs -->
<a href="https://example.com/document.pdf">Download</a>
```

---

## Possible Extensions

- [ ] Recursive scraping (follow internal links)
- [ ] Support for video files (`<video src="...">`)
- [ ] Export results to JSON
- [ ] Add `--url` and `--output` CLI flags with `argparse`
- [ ] Respect `robots.txt`

---

## ️ Disclaimer

This tool is for educational use. Always ensure you have permission before scraping a website. 
Respect the site's `robots.txt` and terms of service.

---

## License

MIT
