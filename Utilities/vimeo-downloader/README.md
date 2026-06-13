# vimeo-downloader

Downloads a Vimeo video at the best available quality and merges it with the
**original audio** into a single, in-sync MP4. It picks the highest-resolution
video stream plus the best audio track and muxes them with ffmpeg, copying the
audio so there is no quality loss or drift.

Works with plain videos, old review links, and the new review links
(`vimeo.com/reviews/<uuid>/videos/<id>`) — for review links it automatically
finds the video's hidden hash, so you just paste the link as-is.

---

## Quick start

```bash
python3 vimeo_downloader.py "PASTE_YOUR_LINK_HERE"
```

**Put the link inside the quotes**, exactly as you copied it from the browser.
Example with a real review link:

```bash
python3 vimeo_downloader.py "https://vimeo.com/reviews/f188456a-e465-49c0-bb96-b3851ea3d588/videos/1200681001"
```

By default it saves to the current folder. To choose where it lands, add `-o`:

```bash
python3 vimeo_downloader.py -o ~/Downloads "PASTE_YOUR_LINK_HERE"
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

## Requirements

Both must be installed and reachable by the Python you run the script with:

```bash
pip install -U yt-dlp
brew install ffmpeg
```

If you get `No module named expat` (a DASH/XML error from a broken Python
install), run the script with a different Python, e.g.
`/usr/local/bin/python3 vimeo_downloader.py ...`.
