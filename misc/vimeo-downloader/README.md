# vimeo-downloader

Downloads a Vimeo video at the best available quality and merges it with the
**original audio** into a single, in-sync MP4. It picks the highest-resolution
video stream plus the best audio track and muxes them with ffmpeg, copying the
audio so there is no quality loss or drift.

Works with plain videos, old review links, and the new review links
(`vimeo.com/reviews/<uuid>/videos/<id>`) — for review links it automatically
finds the video's hidden hash, so you just paste the link as-is.

---

## Setup (do this once)

The tool needs three things: **Python**, **yt-dlp**, and **ffmpeg**. Pick your
operating system below.

### macOS

1. Install [Homebrew](https://brew.sh) if you don't have it (paste this in the
   Terminal app):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
2. Install everything in one line:
   ```bash
   brew install python yt-dlp ffmpeg
   ```
3. Download `vimeo_downloader.py` from this folder (the **Download raw file**
   button on GitHub) into, say, your `Downloads` folder.

On macOS you run the tool with **`python3`**.

### Windows

1. Install **Python** from [python.org/downloads](https://www.python.org/downloads/).
   On the first installer screen, **tick “Add python.exe to PATH”**, then click
   Install.
2. Open **PowerShell** (Start menu, type "PowerShell") and run:
   ```powershell
   winget install yt-dlp.yt-dlp
   winget install Gyan.FFmpeg
   ```
   Then **close and reopen** PowerShell so the new tools are found.
3. Download `vimeo_downloader.py` from this folder (the **Download raw file**
   button on GitHub) into, say, your `Downloads` folder.

On Windows you run the tool with **`python`** (not `python3`).

---

## How to use it

**Step 1 — copy the Vimeo link** from your browser's address bar (the whole
thing, e.g. `https://vimeo.com/reviews/.../videos/1200681001`).

**Step 2 — open a terminal in the folder where you saved the script:**

* **macOS:** in Terminal, type `cd ` (with a space), drag the folder onto the
  window, press Enter.
* **Windows:** open the folder in File Explorer, click the address bar, type
  `powershell`, press Enter.

**Step 3 — run the command, pasting your link inside the quotes:**

macOS:
```bash
python3 vimeo_downloader.py "PASTE_YOUR_LINK_HERE"
```

Windows:
```powershell
python vimeo_downloader.py "PASTE_YOUR_LINK_HERE"
```

That's it — the video downloads to the current folder at best quality.

> Note: everything below shows `python3` (macOS). **On Windows, just replace
> `python3` with `python`.**

A full example with a real review link:
```bash
python3 vimeo_downloader.py "https://vimeo.com/reviews/f188456a-e465-49c0-bb96-b3851ea3d588/videos/1200681001"
```

### Save it somewhere specific

Use `-o` to choose the destination folder:

```bash
# macOS
python3 vimeo_downloader.py -o ~/Downloads "PASTE_YOUR_LINK_HERE"
```
```powershell
# Windows
python vimeo_downloader.py -o "%USERPROFILE%\Downloads" "PASTE_YOUR_LINK_HERE"
```

---

## Choosing the quality

Use `-q`. If you skip it, you get the **best** quality automatically.

| Command | What you get |
|---------|--------------|
| *(nothing)* | Best available (often 2K / 1440p) |
| `-q 1080` | Up to 1080p (Full HD) |
| `-q 720`  | Up to 720p (smaller file) |
| `-q 480`  | Up to 480p (smallest watchable) |
| `-q 2k`   | Up to 1440p |
| `-q audio`| Audio only, no video |

Examples:

```bash
# Best quality (default)
python3 vimeo_downloader.py -o ~/Downloads "PASTE_YOUR_LINK_HERE"

# Full HD 1080p — good quality, smaller file
python3 vimeo_downloader.py -o ~/Downloads -q 1080 "PASTE_YOUR_LINK_HERE"

# Just the audio
python3 vimeo_downloader.py -o ~/Downloads -q audio "PASTE_YOUR_LINK_HERE"
```

> Higher quality = bigger file and longer download. A long video at 2K can be
> several GB. If you only need to watch it, `-q 1080` is usually plenty.

---

## See what's available before downloading

To list every resolution the video offers without downloading anything:

```bash
python3 vimeo_downloader.py -F "PASTE_YOUR_LINK_HERE"
```

---

## All options

| Flag | Meaning |
|------|---------|
| `-o, --outdir DIR` | Where to save the file (default: current folder) |
| `-q, --quality Q`  | `best` (default), `2k`, `1080`, `720`, `480`, `audio` |
| `-p, --password P` | Password, if the video is protected |
| `-F, --list-formats` | List available qualities and exit |
| `-f, --format SEL` | Advanced: raw yt-dlp format selector (overrides `-q`) |

---

## Troubleshooting

* **`python: command not found` / `'python' is not recognized`** — Python isn't
  installed or wasn't added to PATH. Redo the Setup step for your OS (on Windows,
  reinstall Python with “Add to PATH” ticked).
* **`yt-dlp is not installed`** — run `pip install -U yt-dlp` (macOS:
  `pip3 install -U yt-dlp`), or reinstall it from the Setup step.
* **`ffmpeg not found`** — install it from the Setup step (`brew install ffmpeg`
  on macOS, `winget install Gyan.FFmpeg` on Windows).
* **`No module named expat`** (a broken Python install) — on macOS, run the
  script with a different Python, e.g.
  `/usr/local/bin/python3 vimeo_downloader.py ...`.
* **A review link gives "could not find the unlisted hash"** — the link may be
  expired or private. Re-copy a fresh link from the browser.
