#!/usr/bin/env python3
"""Download a Vimeo video at the best available quality with correctly muxed audio.

Wraps yt-dlp + ffmpeg. Picks the highest-resolution video stream and the best
("Original") audio stream, then merges them into a single MP4 with audio copied
(no re-encode), so the sound stays in sync and at full quality.

Handles three kinds of links:
  * Plain video           https://vimeo.com/1200681001
  * Old review link       https://vimeo.com/user123/review/1200681001/3e60323116
  * New review link       https://vimeo.com/reviews/<uuid>/videos/1200681001

The new review format is not understood by yt-dlp directly, so this tool opens
the review page, extracts the video's unlisted hash, and rewrites the URL into
the canonical  https://vimeo.com/<id>/<hash>  form that yt-dlp can download.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"

# https://vimeo.com/reviews/<uuid>/videos/<video_id>
NEW_REVIEW_RE = re.compile(
    r"vimeo\.com/reviews/[0-9a-f-]+/videos/(?P<id>\d+)", re.I
)


def quality_to_format(quality):
    """Map a friendly --quality value to a yt-dlp format selector."""
    if quality is None or quality.lower() == "best":
        return "bv*+ba/b"                       # best video + best audio
    q = quality.lower()
    if q in ("audio", "sound", "mp3", "m4a"):
        return "ba/b"                           # audio only
    aliases = {"4k": 2160, "2k": 1440, "fhd": 1080, "hd": 720}
    if q in aliases:
        height = aliases[q]
    else:
        height = int(q.replace("p", ""))        # e.g. "1080", "1080p", "720"
    # Cap the video height, still take the best audio.
    return f"bv*[height<={height}]+ba/b[height<={height}]"


# Common Homebrew locations in case ffmpeg isn't on PATH in this shell.
FFMPEG_FALLBACKS = ["/opt/homebrew/bin/ffmpeg", "/usr/local/bin/ffmpeg"]


def require(tool):
    if shutil.which(tool) is None:
        print(f"[!] Missing dependency: {tool}")
        sys.exit(1)


def ytdlp_base():
    """Return the command prefix to run yt-dlp.

    Prefer running it as a module with the current interpreter, so it shares the
    same Python (and its working C extensions, e.g. expat for DASH parsing).
    Fall back to a yt-dlp binary on PATH only if the module isn't importable.
    """
    try:
        import yt_dlp  # noqa: F401
        return [sys.executable, "-m", "yt_dlp"]
    except ImportError:
        pass
    if shutil.which("yt-dlp"):
        return ["yt-dlp"]
    print("[!] yt-dlp is not installed.")
    print(f"    Install with: {sys.executable} -m pip install -U yt-dlp")
    sys.exit(1)


def find_ffmpeg():
    """Locate the ffmpeg binary, falling back to common Homebrew paths."""
    path = shutil.which("ffmpeg")
    if path:
        return path
    for cand in FFMPEG_FALLBACKS:
        if os.path.exists(cand):
            return cand
    print("[!] ffmpeg not found.")
    print("    Install with: brew install ffmpeg")
    sys.exit(1)


def resolve_review_url(url):
    """Turn a new-style review link into a canonical unlisted-video URL.

    Returns (download_url, referer). For any other URL it is returned as-is.
    """
    m = NEW_REVIEW_RE.search(url)
    if not m:
        return url, None

    require("curl")
    video_id = m.group("id")
    print(f"[*] Detected review link, resolving unlisted hash for {video_id}...")

    html = subprocess.run(
        ["curl", "-sL", "-A", UA, url],
        capture_output=True, text=True, check=False,
    ).stdout

    # The review page embeds a player config URL carrying the unlisted hash as h=...
    hm = re.search(r"video/%s/config[^\"']*?h=([a-f0-9]+)" % video_id, html, re.I)
    if not hm:
        hm = re.search(r"\bh=([a-f0-9]{8,})", html, re.I)
    if not hm:
        print("[!] Could not find the unlisted hash on the review page.")
        print("    The link may be expired, private, or require sign-in.")
        sys.exit(1)

    unlisted_hash = hm.group(1)
    download_url = f"https://vimeo.com/{video_id}/{unlisted_hash}"
    print(f"[*] Resolved -> {download_url}")
    return download_url, url


def list_formats(url):
    dl_url, referer = resolve_review_url(url)
    cmd = ytdlp_base() + ["-F"]
    if referer:
        cmd += ["--referer", referer]
    cmd.append(dl_url)
    subprocess.run(cmd, check=False)


def download(url, outdir, password=None, fmt=None):
    ffmpeg = find_ffmpeg()

    dl_url, referer = resolve_review_url(url)
    os.makedirs(outdir, exist_ok=True)

    # bv*+ba -> best video + best audio, merged by ffmpeg.
    # /b     -> single best progressive stream if separate ones are unavailable.
    format_selector = fmt or "bv*+ba/b"

    cmd = ytdlp_base() + [
        "-f", format_selector,
        "--merge-output-format", "mp4",
        "--ffmpeg-location", ffmpeg,
        "-o", os.path.join(outdir, "%(title)s [%(id)s].%(ext)s"),
        "--no-playlist",
        "--retries", "10",
        "--fragment-retries", "10",
        "--concurrent-fragments", "4",
    ]
    if referer:
        cmd += ["--referer", referer]
    if password:
        cmd += ["--video-password", password]
    cmd.append(dl_url)

    print(f"[*] Format     : {format_selector}")
    print(f"[*] Output dir : {outdir}")
    result = subprocess.run(cmd, check=False)

    if result.returncode == 0:
        print("[+] Done.")
    else:
        print(f"[!] yt-dlp exited with code {result.returncode}")
        sys.exit(result.returncode)


def main():
    parser = argparse.ArgumentParser(
        description="Download a Vimeo video at best quality with accurate audio."
    )
    parser.add_argument("url", help="Vimeo URL (plain, old review, or new review link)")
    parser.add_argument(
        "-o", "--outdir", default=".", help="Output directory (default: current dir)"
    )
    parser.add_argument(
        "-p", "--password", help="Video password, if the video is protected"
    )
    parser.add_argument(
        "-q", "--quality",
        help="Quality: best (default), 2k, 1440, 1080, 720, 480, or 'audio' for "
             "audio-only. Picks the highest video up to that height.",
    )
    parser.add_argument(
        "-f", "--format",
        help="Advanced: raw yt-dlp format selector. Overrides --quality.",
    )
    parser.add_argument(
        "-F", "--list-formats", action="store_true",
        help="List available formats and exit (does not download)",
    )
    args = parser.parse_args()

    if args.list_formats:
        list_formats(args.url)
        return

    fmt = args.format or quality_to_format(args.quality)
    download(args.url, args.outdir, password=args.password, fmt=fmt)


if __name__ == "__main__":
    main()
