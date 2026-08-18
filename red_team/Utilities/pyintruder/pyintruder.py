#!/usr/bin/env python3
"""
PyIntruder - a fast, universal Burp-Intruder-style fuzzer for AUTHORIZED
web pentesting / PortSwigger labs.

Why: Burp Community throttles Intruder on purpose (~1 req/s). This tool uses
httpx + asyncio to fire many requests concurrently, and writes an interactive,
filterable HTML report similar to the Intruder results window.

Attack types : sniper, battering ram, pitchfork, cluster bomb
Payloads     : number range, wordlist file, inline list
Extras       : optional session re-login/refresh (with CSRF extraction) for
               apps that log you out mid brute-force.

For authorized testing only.
"""

import argparse
import asyncio
import html
import itertools
import json
import re
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

try:
    import httpx
except ImportError:
    sys.exit("Missing dependency. Run:  pip install 'httpx[http2]'")


MARK = "§"  # § , same marker Burp uses


# --------------------------------------------------------------------------- #
# Small interactive helpers
# --------------------------------------------------------------------------- #
def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    try:
        val = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        val = ""
    return val or (default if default is not None else "")


def ask_int(prompt, default):
    while True:
        val = ask(prompt, str(default))
        try:
            return int(val)
        except ValueError:
            print(f"  (please type a number, or just press Enter for {default})")


def ask_yes(prompt, default=False):
    d = "Y/n" if default else "y/N"
    val = input(f"{prompt} [{d}]: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


def read_block(prompt, sentinel="EOF"):
    """Read multiple lines from stdin until a line == sentinel."""
    print(f"{prompt}  (end with a line containing only '{sentinel}')")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == sentinel:
            break
        lines.append(line)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Raw HTTP request parsing
# --------------------------------------------------------------------------- #
def parse_request(raw):
    raw = raw.replace("\r\n", "\n").lstrip("\n")
    if "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head, body = raw, ""
    lines = head.split("\n")
    parts = lines[0].split(" ")
    method = parts[0] if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"

    headers = {}
    host = None
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if not k:
            continue
        if k.lower() == "host":
            host = v
        headers[k] = v

    # Burp pastes usually carry one trailing newline on the body; drop it.
    if body.endswith("\n"):
        body = body[:-1]
    return {"method": method, "path": path, "headers": headers,
            "host": host, "body": body}


def snippet_text(text, n):
    """Visible-text snippet of a response, for in-browser searching.
    Strips <script>/<style>, drops tags, collapses whitespace, caps length."""
    if n <= 0:
        return ""
    t = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:n]


# Headers httpx must control itself (or that break decoding).
_DROP_HEADERS = {"host", "content-length", "accept-encoding"}


def clean_headers(headers, cookie=None):
    out = {}
    for k, v in headers.items():
        if k.lower() in _DROP_HEADERS:
            continue
        if cookie is not None and k.lower() == "cookie":
            continue
        out[k] = v
    if cookie is not None:
        out["Cookie"] = cookie
    return out


# --------------------------------------------------------------------------- #
# Auto-marking of payload positions
# --------------------------------------------------------------------------- #
def auto_mark(text):
    """Wrap every param value (foo=BAR) in § markers. Works on query & body."""
    def repl(m):
        return f"{m.group(1)}={MARK}{m.group(2)}{MARK}"
    # key=value  where value stops at & or end
    return re.sub(r"([\w.\-\[\]%]+)=([^&\s]*)", repl, text)


def split_query(path):
    if "?" in path:
        base, q = path.split("?", 1)
        return base, q
    return path, None


def tokenize(marked, offset):
    """
    Turn a §-marked string into tokens. Marker tokens store a GLOBAL index
    (offset + local order). Returns (tokens, originals).
    """
    parts = marked.split(MARK)
    tokens, originals = [], []
    for i, part in enumerate(parts):
        if i % 2 == 0:
            tokens.append(("lit", part))
        else:
            idx = offset + len(originals)
            originals.append(part)
            tokens.append(("mark", idx))
    return tokens, originals


def build(tokens, assignment):
    out = []
    for kind, val in tokens:
        out.append(val if kind == "lit" else str(assignment[val]))
    return "".join(out)


# --------------------------------------------------------------------------- #
# Attack job generation
# --------------------------------------------------------------------------- #
def make_jobs(attack, n_markers, originals, payload_sets):
    """
    Yield (assignment_list, label) tuples.
    payload_sets: list-of-lists (one per position) OR single list for
    sniper / battering ram.
    """
    jobs = []
    if attack == "sniper":
        plist = payload_sets[0]
        for pos in range(n_markers):
            for p in plist:
                a = list(originals)
                a[pos] = p
                jobs.append((a, f"[{pos}] {p}"))
    elif attack == "battering":
        plist = payload_sets[0]
        for p in plist:
            jobs.append(([p] * n_markers, p))
    elif attack == "pitchfork":
        for combo in zip(*payload_sets):
            jobs.append((list(combo), " | ".join(combo)))
    elif attack == "cluster":
        for combo in itertools.product(*payload_sets):
            jobs.append((list(combo), " | ".join(combo)))
    return jobs


# --------------------------------------------------------------------------- #
# Rate limiter
# --------------------------------------------------------------------------- #
class RateLimiter:
    def __init__(self, rps):
        self.interval = 1.0 / rps
        self.lock = asyncio.Lock()
        self.next = 0.0

    async def acquire(self):
        async with self.lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            wait = self.next - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = loop.time()
            self.next = now + self.interval


# --------------------------------------------------------------------------- #
# Session refresh (re-login) engine
# --------------------------------------------------------------------------- #
class Refresh:
    """
    Runs a sequence of raw requests sharing a cookie jar, extracting dynamic
    values (e.g. CSRF tokens) for use as {{NAME}} placeholders in later
    refresh requests AND in the attack request itself.
    """
    def __init__(self, requests, extractors, base_cookie):
        self.requests = requests          # list of parsed requests (raw text)
        self.extractors = extractors      # list of (name, compiled_regex)
        self.base_cookie = base_cookie

    @staticmethod
    def _apply_placeholders(text, values):
        for name, val in values.items():
            text = text.replace("{{" + name + "}}", val)
        return text

    async def run(self, client, scheme):
        # seed jar from the original request's cookies
        jar = {}
        for chunk in self.base_cookie.split(";"):
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                jar[k.strip()] = v.strip()

        values = {}
        for raw in self.requests:
            raw = self._apply_placeholders(raw, values)
            req = parse_request(raw)
            cookie = "; ".join(f"{k}={v}" for k, v in jar.items())
            headers = clean_headers(req["headers"], cookie=cookie)
            url = f"{scheme}://{req['host']}{req['path']}"
            resp = await client.request(req["method"], url,
                                        headers=headers,
                                        content=req["body"].encode(),
                                        follow_redirects=False)
            for k, v in resp.cookies.items():
                jar[k] = v
            text = resp.text
            for name, rx in self.extractors:
                m = rx.search(text)
                if m:
                    values[name] = m.group(1) if m.groups() else m.group(0)

        cookie = "; ".join(f"{k}={v}" for k, v in jar.items())
        return cookie, values


# --------------------------------------------------------------------------- #
# The attack runner
# --------------------------------------------------------------------------- #
async def run_attack(cfg):
    limits = httpx.Limits(max_connections=cfg["concurrency"],
                          max_keepalive_connections=cfg["concurrency"])
    verify = not cfg["insecure"]
    client_kwargs = dict(follow_redirects=False, timeout=cfg["timeout"], limits=limits)
    if cfg.get("proxy"):
        client_kwargs["proxy"] = cfg["proxy"]
        verify = False  # Burp/mitm re-signs TLS; don't verify its cert
        print(f"[*] Routing through proxy {cfg['proxy']} (TLS verify off)")
    client_kwargs["verify"] = verify
    try:
        client = httpx.AsyncClient(http2=cfg["http2"], **client_kwargs)
    except Exception:
        print("[!] HTTP/2 unavailable (install 'httpx[http2]'). Falling back to HTTP/1.1.")
        client = httpx.AsyncClient(http2=False, **client_kwargs)

    state = {"cookie": cfg["base_cookie"], "values": {}}
    state_lock = asyncio.Lock()
    refresh_lock = asyncio.Lock()
    rate = RateLimiter(cfg["rate"]) if cfg["rate"] else None
    sem = asyncio.Semaphore(cfg["concurrency"])
    grep_rx = cfg["grep_rx"]
    refresh = cfg["refresh"]
    trigger_codes = cfg["trigger_codes"]
    trigger_rx = cfg["trigger_rx"]

    results = []
    total = len(cfg["jobs"])
    done = 0

    # live anomaly detector: learn a baseline from the first responses, then
    # shout (without stopping) the first time each new kind of outlier appears.
    len_counts, status_counts, alerted = {}, {}, set()
    WARMUP = 25

    def flag(rec, base_status, base_len):
        sig = (rec["status"], rec["length"], bool(rec["matched"]))
        if sig in alerted:
            return
        alerted.add(sig)
        tag = "match" if rec["matched"] else "anomaly"
        extra = f"  ->{rec['redirect']}" if rec["redirect"] else ""
        print(f"\n  \033[1;33m🚨 {tag}\033[0m  payload '{rec['payload']}'  "
              f"status {rec['status']}, len {rec['length']}  "
              f"(baseline status {base_status}, len {base_len}){extra}\a",
              flush=True)

    def check_anomaly(rec):
        if rec["error"]:
            return
        len_counts[rec["length"]] = len_counts.get(rec["length"], 0) + 1
        status_counts[rec["status"]] = status_counts.get(rec["status"], 0) + 1
        if sum(len_counts.values()) < WARMUP:
            return
        base_len = max(len_counts, key=len_counts.get)
        base_status = max(status_counts, key=status_counts.get)
        # on first reaching warmup, sweep the backlog; afterwards just this one
        batch = results if sum(len_counts.values()) == WARMUP else [rec]
        for r in batch:
            if r["error"]:
                continue
            if r["matched"] or r["status"] != base_status or r["length"] != base_len:
                flag(r, base_status, base_len)

    def render_request(assignment, values):
        path = build(cfg["path_tokens"], assignment)
        body = build(cfg["body_tokens"], assignment)
        # attack request may also carry {{NAME}} tokens seeded by refresh
        for name, val in values.items():
            ph = "{{" + name + "}}"
            path = path.replace(ph, val)
            body = body.replace(ph, val)
        return path, body

    def triggered(resp):
        if resp.status_code in trigger_codes:
            return True
        if trigger_rx and trigger_rx.search(resp.text):
            return True
        return False

    async def do_refresh():
        async with refresh_lock:
            cookie, values = await refresh.run(client, cfg["scheme"])
            async with state_lock:
                state["cookie"] = cookie
                state["values"] = values

    async def do_job(assignment, label):
        nonlocal done
        async with sem:
            if rate:
                await rate.acquire()
            record = {"payload": label, "status": 0, "length": 0, "words": 0,
                      "time_ms": 0, "matched": False, "redirect": "", "error": "",
                      "path": "", "reqbody": "", "cookie": "",
                      "respbody": "", "resphdrs": ""}
            for attempt in range(3):
                async with state_lock:
                    cookie = state["cookie"]
                    values = dict(state["values"])
                path, body = render_request(assignment, values)
                url = f"{cfg['scheme']}://{cfg['host']}{path}"
                headers = clean_headers(cfg["headers"], cookie=cookie)
                record["path"] = path
                record["reqbody"] = body
                record["cookie"] = cookie
                t0 = time.perf_counter()
                try:
                    resp = await client.request(cfg["method"], url,
                                                headers=headers,
                                                content=body.encode())
                except Exception as e:
                    record["error"] = f"{type(e).__name__}: {e}"
                    break
                dt = (time.perf_counter() - t0) * 1000

                if refresh and triggered(resp) and attempt < 2:
                    await do_refresh()
                    continue  # retry the same payload with fresh session

                text = resp.text
                cap = cfg["body_cap"]
                hdr_bits = [f"HTTP {resp.status_code}"]
                for h in ("content-type", "content-length", "location", "set-cookie"):
                    if h in resp.headers:
                        hdr_bits.append(f"{h}: {resp.headers[h]}")
                record.update(
                    status=resp.status_code,
                    length=len(resp.content),
                    words=len(text.split()),
                    time_ms=round(dt),
                    matched=bool(grep_rx.search(text)) if grep_rx else False,
                    redirect=resp.headers.get("location", ""),
                    respbody=text[:cap],
                    resphdrs="\n".join(hdr_bits),
                )
                break

            results.append(record)
            check_anomaly(record)
            done += 1
            if done % 25 == 0 or done == total:
                print(f"\r  sent {done}/{total}", end="", flush=True)

    # optional startup login to seed cookies + tokens
    if refresh:
        print("[*] Startup session refresh (login)...")
        await do_refresh()

    print(f"[*] Firing {total} requests (concurrency={cfg['concurrency']})...")
    t0 = time.perf_counter()
    await asyncio.gather(*(do_job(a, l) for a, l in cfg["jobs"]))
    elapsed = time.perf_counter() - t0
    print(f"\n[*] Done in {elapsed:.1f}s"
          + (f" — flagged {len(alerted)} kind(s) of anomaly during the run"
             if alerted else " — no anomalies stood out"))

    await client.aclose()
    for i, r in enumerate(results):
        r["id"] = i + 1
    return results, elapsed


# --------------------------------------------------------------------------- #
# HTML report
# --------------------------------------------------------------------------- #
HTML_TEMPLATE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>PyIntruder Results</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{font:13px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#111318;color:#d7dbe0}
header{padding:16px 18px 12px}
h1{font-size:16px;margin:0 0 2px}
.meta{color:#7f8894;font-size:12px}
.bar{position:sticky;top:0;z-index:3;background:#181b21;border-top:1px solid #262b33;
  border-bottom:1px solid #262b33;padding:10px 18px;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.field{display:flex;flex-direction:column;gap:2px}
.field small{color:#6f7883;font-size:10px;text-transform:uppercase;letter-spacing:.4px}
.row2{display:flex;gap:4px}
input[type=text],select{background:#0e1014;border:1px solid #2a303a;color:#e6eaef;
  padding:6px 8px;border-radius:6px;font-size:13px;outline:none}
input[type=text]:focus,select:focus{border-color:#4c8bf5}
input#q{min-width:150px}input#resp{min-width:180px}input#statusf{width:90px}
.checks{display:flex;gap:14px;align-items:center;margin-left:4px}
.checks label{color:#aab2bd;display:flex;gap:5px;align-items:center;cursor:pointer;font-size:12px}
#count{margin-left:auto;color:#7f8894;font-size:12px;white-space:nowrap}
/* NOTE: no overflow here — overflow-x:auto also makes overflow-y:auto, which
   turns this into the scroll container and breaks the sticky header. */
.wrap{width:100%}
table{border-collapse:collapse;width:100%;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
th,td{padding:6px 12px;text-align:left;border-bottom:1px solid #1e232b;white-space:nowrap}
th{position:sticky;top:52px;z-index:2;background:#181b21;cursor:pointer;user-select:none;color:#aab2bd;font-weight:600}
th:hover{color:#fff}
th .arw{color:#4c8bf5;font-size:10px}
td.payload{font-weight:600;color:#eef1f5;max-width:360px;overflow:hidden;text-overflow:ellipsis}
td.resp{color:#9aa2ac;max-width:520px;overflow:hidden;text-overflow:ellipsis;font-family:inherit}
tr.anom td{background:#16241a}
tr.anom td.payload{color:#83e08a}
tr.match td{background:#2a2412}
tr.match td.payload{color:#ffd166}
td.err{color:#ff6b6b}
.badge{padding:1px 7px;border-radius:4px;font-size:11px}
.s2{background:#1f3b1f;color:#8fe28f}.s3{background:#3b331f;color:#ffd166}
.s4{background:#3b1f1f;color:#ff9b9b}.s5{background:#3b1f36;color:#ff9bd1}
tbody tr{cursor:pointer}
tbody tr:hover td{background:#20262f}
.hint{color:#6f7883;font-size:12px;margin:10px 18px}
#scrim{position:fixed;inset:0;background:rgba(0,0,0,.45);opacity:0;pointer-events:none;
  transition:opacity .18s;z-index:9}
#scrim.open{opacity:1;pointer-events:auto}
#drawer{position:fixed;top:0;right:-100%;height:100vh;width:min(620px,94vw);
  background:#0f1216;border-left:1px solid #262b33;box-shadow:-14px 0 46px rgba(0,0,0,.55);
  transition:right .2s ease;z-index:10;display:flex;flex-direction:column}
#drawer.open{right:0}
.dhead{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;
  padding:14px 16px;border-bottom:1px solid #262b33}
.dpay{display:block;font-family:ui-monospace,Menlo,monospace;font-weight:700;
  color:#eef1f5;font-size:15px}
.dmeta{display:block;color:#9aa2ac;font-size:12px;margin-top:4px}
#dclose{background:#1c232c;border:1px solid #2a303a;color:#c7d0da;border-radius:8px;
  width:30px;height:30px;cursor:pointer;font-size:14px;flex:none}
#dclose:hover{color:#fff;border-color:#3a4351}
.dbody{overflow:auto;padding:6px 16px 26px;display:flex;flex-direction:column;gap:16px}
.pane .plabel{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#6f7883;
  margin:14px 0 6px}
.blk{margin:0;background:#0b0e12;border:1px solid #212832;border-radius:9px;padding:12px 13px;
  font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;line-height:1.55;
  color:#c7d0da;white-space:pre-wrap;word-break:break-word;max-height:none}
@media (max-width:560px){#drawer{width:100vw}}
</style></head><body>
<header><h1>PyIntruder — Attack Results</h1><div class="meta">__META__</div></header>
<div class="bar">
  <div class="field"><small>payload</small><input type="text" id="q" placeholder="contains…"></div>
  <div class="field"><small>response body</small>
    <div class="row2">
      <select id="respMode"><option value="has">contains</option><option value="not">does NOT contain</option></select>
      <input type="text" id="resp" placeholder="e.g. wrong / Congratulations">
    </div>
  </div>
  <div class="field"><small>status</small><input type="text" id="statusf" placeholder="e.g. 30"></div>
  <div class="checks">
    <label><input type="checkbox" id="anom"> anomalies only</label>
    <label><input type="checkbox" id="grep"> matched only</label>
  </div>
  <span id="count"></span>
</div>
<div class="wrap"><table id="t"><thead><tr>
  <th data-k="id">#</th><th data-k="payload">Payload</th><th data-k="status">Status</th>
  <th data-k="length">Length</th><th data-k="words">Words</th><th data-k="time_ms">Time&nbsp;ms</th>
  <th data-k="redirect">Redirect</th>
</tr></thead><tbody></tbody></table></div>
<p class="hint">Tip: click any row to see the full request &amp; response on the right.</p>

<div id="scrim"></div>
<aside id="drawer" aria-hidden="true">
  <div class="dhead">
    <div><span id="dpay" class="dpay"></span><span id="dmeta" class="dmeta"></span></div>
    <button id="dclose" title="Close (Esc)">✕</button>
  </div>
  <div class="dbody">
    <div class="pane"><div class="plabel">Request</div><pre id="dreq" class="blk"></pre></div>
    <div class="pane"><div class="plabel">Response</div><pre id="dresp" class="blk"></pre></div>
  </div>
</aside>
<script>
const RESULTS = __DATA__;
const BASE = __BASE__;
const REQ = __REQ__;
const BODIES = __BODIES__;   // de-duplicated response bodies
const HDRS = __HDRS__;       // de-duplicated response header blocks
const COOKIES = __COOKIES__; // de-duplicated request cookies
const CAP = 800;             // max rows drawn at once (keeps the page snappy)
let sortKey="id", sortDir=1;
const el=id=>document.getElementById(id);

const bodyOf=r=>BODIES[r.bi]||"";
const hdrsOf=r=>HDRS[r.hi]||"";
const cookieOf=r=>COOKIES[r.ci]||"";

function isAnom(r){ return r.status!==BASE.status || r.length!==BASE.length; }
function interesting(r){ return r.matched || isAnom(r); }
function sBadge(s){ if(!s) return ""; return `<span class="badge s${String(s)[0]}">${s}</span>`; }

function passes(r){
  const q=el("q").value.toLowerCase();
  if(q && !String(r.payload).toLowerCase().includes(q)) return false;
  const rt=el("resp").value.toLowerCase();
  if(rt){ const has=bodyOf(r).toLowerCase().includes(rt);
    if(el("respMode").value==="not" ? has : !has) return false; }
  const sf=el("statusf").value.trim();
  if(sf && !String(r.status).includes(sf)) return false;
  if(el("anom").checked && !isAnom(r)) return false;
  if(el("grep").checked && !r.matched) return false;
  return true;
}
function render(){
  let rows=RESULTS.filter(passes);
  rows.sort((a,b)=>{const x=a[sortKey],y=b[sortKey];return (x>y?1:x<y?-1:0)*sortDir;});
  // draw at most CAP rows, but never hide an anomaly/match — append any that
  // fell past the cap so the winner is always on screen.
  let shown=rows.slice(0,CAP);
  let extra=0;
  if(rows.length>CAP){
    const set=new Set(shown);
    for(const r of rows){ if(interesting(r) && !set.has(r)){ shown.push(r); extra++; } }
  }
  const tb=document.querySelector("#t tbody"); tb.innerHTML="";
  const frag=document.createDocumentFragment();
  for(const r of shown){
    const tr=document.createElement("tr");
    tr.dataset.id=r.id;
    if(r.matched) tr.className="match"; else if(isAnom(r)) tr.className="anom";
    tr.innerHTML=`<td>${r.id}</td><td class="payload">${escapeHtml(r.payload)}</td>`+
      `<td>${sBadge(r.status)}</td><td>${r.length}</td><td>${r.words}</td>`+
      `<td>${r.time_ms}</td><td>${escapeHtml(r.redirect||"")}</td>`;
    frag.appendChild(tr);
  }
  tb.appendChild(frag);
  const capped = rows.length>CAP;
  el("count").textContent = capped
    ? `showing ${CAP}${extra?`+${extra}`:""} of ${rows.length} — refine the filter to see more`
    : `${rows.length} / ${RESULTS.length} shown`;
  document.querySelectorAll("th").forEach(th=>{
    th.innerHTML = th.dataset.k===sortKey
      ? `${labelOf(th.dataset.k)} <span class="arw">${sortDir>0?"▲":"▼"}</span>`
      : labelOf(th.dataset.k);
  });
}
function labelOf(k){return {id:"#",payload:"Payload",status:"Status",length:"Length",
  words:"Words",time_ms:"Time&nbsp;ms",redirect:"Redirect"}[k];}
function escapeHtml(s){return String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}

function reqText(r){
  const L=[`${REQ.method} ${r.path} HTTP/${REQ.httpver}`, `Host: ${REQ.host}`];
  for(const [k,v] of REQ.headers){ if(k.toLowerCase()==="cookie") continue; L.push(`${k}: ${v}`); }
  const ck=cookieOf(r); if(ck) L.push(`Cookie: ${ck}`);
  L.push(""); L.push(r.reqbody||"");
  return L.join("\n");
}
function respText(r){
  if(r.error) return "[connection error] "+r.error;
  const body=bodyOf(r);
  let out=hdrsOf(r)+"\n\n"+body;
  if(body && r.length>body.length)
    out+="\n\n…(response body truncated in the report — "+r.length+" bytes total)";
  return out;
}
function openDrawer(id){
  const r=RESULTS.find(x=>x.id===id); if(!r) return;
  el("dpay").textContent=r.payload;
  el("dmeta").innerHTML=`${sBadge(r.status)} &nbsp;len ${r.length} &nbsp;· ${r.time_ms} ms`+
    (r.redirect?` &nbsp;· →${escapeHtml(r.redirect)}`:"");
  el("dreq").textContent=reqText(r);
  el("dresp").textContent=respText(r);
  el("drawer").classList.add("open"); el("scrim").classList.add("open");
  el("drawer").setAttribute("aria-hidden","false");
}
function closeDrawer(){
  el("drawer").classList.remove("open"); el("scrim").classList.remove("open");
  el("drawer").setAttribute("aria-hidden","true");
}
document.querySelector("#t tbody").addEventListener("click",e=>{
  const tr=e.target.closest("tr"); if(tr&&tr.dataset.id) openDrawer(+tr.dataset.id);
});
el("dclose").onclick=closeDrawer; el("scrim").onclick=closeDrawer;
document.addEventListener("keydown",e=>{ if(e.key==="Escape") closeDrawer(); });
document.querySelectorAll("th").forEach(th=>th.onclick=()=>{
  const k=th.dataset.k; if(k===sortKey) sortDir*=-1; else {sortKey=k;sortDir=(k==="id"?1:-1);} render();
});
["q","resp","statusf"].forEach(id=>el(id).oninput=render);
["respMode","anom","grep"].forEach(id=>el(id).onchange=render);
// The filter bar wraps on narrow widths, so its height varies. Pin the sticky
// column header exactly to the bar's real height so it never sits on a row.
function syncStickyTop(){
  const bar=document.querySelector(".bar"); if(!bar) return;
  const h=Math.round(bar.getBoundingClientRect().height);
  document.querySelectorAll("#t thead th").forEach(th=>{ th.style.top=h+"px"; });
}
window.addEventListener("resize", syncStickyTop);
window.addEventListener("load", syncStickyTop);
syncStickyTop();
render();
</script></body></html>"""


def most_common(values):
    counts = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    return max(counts, key=counts.get) if counts else 0


def _dedup(results, field, idx_field):
    """Move a repeated per-row field into a shared pool, leaving an index.
    Brute-force runs repeat the same response thousands of times — storing it
    once instead of per row shrinks the report from tens of MB to ~1 MB."""
    pool, arr = {}, []
    for r in results:
        v = r.pop(field, "")
        i = pool.get(v)
        if i is None:
            i = len(arr)
            pool[v] = i
            arr.append(v)
        r[idx_field] = i
    return arr


def js_json(obj):
    """json.dumps, but safe to embed inside an HTML <script> block.
    Response bodies routinely contain '</script>', which would otherwise close
    our script tag early and break the whole page. Escaping '</' as '<\\/' keeps
    the JSON valid while hiding the closing tag from the HTML parser."""
    return (json.dumps(obj)
            .replace("</", "<\\/")
            .replace("<!--", "<\\!--")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def write_report(results, meta, out_path, req_ctx):
    base = {"status": most_common([r["status"] for r in results]),
            "length": most_common([r["length"] for r in results])}
    # de-duplicate the big/repeated fields into shared pools
    bodies = _dedup(results, "respbody", "bi")
    hdrs = _dedup(results, "resphdrs", "hi")
    cookies = _dedup(results, "cookie", "ci")
    # safety net: if there are many *distinct* large bodies, cap the total so the
    # report file stays reasonable. (The common brute-force case dedups to a
    # handful of bodies and never hits this.)
    BUDGET = 6_000_000
    total = sum(len(b) for b in bodies)
    if total > BUDGET and bodies:
        per = max(1000, BUDGET // len(bodies))
        bodies = [b[:per] for b in bodies]
    html_doc = (HTML_TEMPLATE
                .replace("__DATA__", js_json(results))
                .replace("__BASE__", js_json(base))
                .replace("__REQ__", js_json(req_ctx))
                .replace("__BODIES__", js_json(bodies))
                .replace("__HDRS__", js_json(hdrs))
                .replace("__COOKIES__", js_json(cookies))
                .replace("__META__", html.escape(meta)))
    out = Path(out_path)
    if out.parent != Path(""):
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html_doc, encoding="utf-8")


# --------------------------------------------------------------------------- #
# Interactive config
# --------------------------------------------------------------------------- #
ATTACK_HELP = {
    "sniper":
        "SNIPER — one payload list. Each marked spot is attacked one at a time\n"
        "  while the other spots keep their original value. This is the classic,\n"
        "  most-used mode. Perfect for a single spot like a 4-digit code, a\n"
        "  username, an id, etc.  (requests = spots x payloads)",
    "battering":
        "BATTERING RAM — one payload list, but the SAME value is placed into\n"
        "  EVERY marked spot at the same time. Rare — used when one value must\n"
        "  repeat in several places.  (requests = payloads)",
    "pitchfork":
        "PITCHFORK — a SEPARATE list per spot, walked in parallel: 1st item of\n"
        "  list A goes with 1st of list B, 2nd with 2nd, and so on. Great for\n"
        "  known username+password PAIRS.  (requests = length of shortest list)",
    "cluster":
        "CLUSTER BOMB — a separate list per spot, trying EVERY combination\n"
        "  (A x B x C ...). Counts explode fast. Good for spraying usernames x\n"
        "  passwords.  (requests = A x B x C ...)",
}


def choose_attack(n_markers):
    print("\nWhich attack type? (press Enter for sniper)")
    print("  [1] sniper     - 1 list, one marked spot at a time   (most common)")
    print("  [2] battering  - 1 list, same value in all spots")
    print("  [3] pitchfork  - a list per spot, in parallel (pairs)")
    print("  [4] cluster    - a list per spot, ALL combinations")
    print("  [?] explain each one in detail")
    order = ("sniper", "battering", "pitchfork", "cluster")
    while True:
        c = ask("choice", "1")
        if c == "?":
            print()
            for k in order:
                print(ATTACK_HELP[k] + "\n")
            continue
        attack = {"1": "sniper", "2": "battering",
                  "3": "pitchfork", "4": "cluster"}.get(c)
        if not attack:
            print("  (please type 1, 2, 3, 4, or ? )")
            continue
        if n_markers == 1 and attack in ("pitchfork", "cluster"):
            print("  (you only marked 1 spot — sniper fits best, but going with your pick)")
        return attack


def pick_file():
    """Open a native file chooser when possible; otherwise ask for a path."""
    if sys.platform == "darwin":
        try:
            out = subprocess.run(
                ["osascript", "-e",
                 'POSIX path of (choose file with prompt "Select a wordlist")'],
                capture_output=True, text=True, timeout=180)
            p = out.stdout.strip()
            if p:
                print(f"  selected: {p}")
                return p
        except Exception:
            pass
    else:
        try:
            import tkinter
            from tkinter import filedialog
            root = tkinter.Tk(); root.withdraw()
            p = filedialog.askopenfilename(title="Select a wordlist")
            root.destroy()
            if p:
                print(f"  selected: {p}")
                return p
        except Exception:
            pass
    return ask("path to wordlist file")


def get_payload_list(label=""):
    print(f"\nWhat should I try in the marked spot{(' ' + label) if label else ''}?")
    print("  [1] a range of numbers (e.g. 0000-9999)")
    print("  [2] a wordlist file (one item per line)")
    print("  [3] a short list you type here")
    c = ask("choice", "1")
    if c == "2":
        print("  opening a file picker… (or type a path if no window appears)")
        p = pick_file()
        return [ln.rstrip("\n") for ln in open(p, encoding="utf-8", errors="ignore") if ln.strip()]
    if c == "3":
        return [x.strip() for x in ask("items, comma-separated").split(",") if x.strip()]
    start = ask_int("first number", 0)
    end = ask_int("last number", 9999)
    step = ask_int("count by (Enter = 1)", 1)
    # keep leading zeros so 5 -> 0005 when the range is 4 digits wide
    width = ask_int("digits / zero-pad width (Enter = auto)", len(str(end)))
    return [str(n).zfill(width) for n in range(start, end + 1, step)]


def build_config():
    print("=== PyIntruder — authorized testing only ===\n")

    # 1. request
    req_arg = None
    for i, a in enumerate(sys.argv):
        if a == "--request" and i + 1 < len(sys.argv):
            req_arg = sys.argv[i + 1]
    if req_arg:
        raw = Path(req_arg).read_text(encoding="utf-8")
    else:
        raw = read_block("Paste the raw HTTP request:")
    req = parse_request(raw)
    if not req["host"]:
        req["host"] = ask("Host (no Host header found)")

    scheme = "https"
    for i, a in enumerate(sys.argv):
        if a == "--scheme" and i + 1 < len(sys.argv):
            scheme = sys.argv[i + 1]

    # 2. auto-mark + confirm loop
    base_path, query = split_query(req["path"])
    body = req["body"]
    query_marked_final = None
    body_marked_final = ""
    while True:
        marked_query = auto_mark(query) if query else None
        marked_body = auto_mark(body) if body else ""
        shown_path = base_path + (("?" + marked_query) if marked_query else "")
        print("\n--- auto-marked positions (highlighted with §…§) ---")
        print(f"{req['method']} {shown_path}")
        if marked_body:
            print(f"\n{marked_body}")
        n = (marked_query or "").count(MARK) // 2 + (marked_body or "").count(MARK) // 2
        print(f"--- {n} position(s) marked ---")
        choice = ask("Accept these positions? [y]es / [m]anual", "y").lower()
        if choice.startswith("y"):
            query_marked_final = marked_query
            body_marked_final = marked_body
            break
        # manual: user types exact substrings to mark
        print("Manual mode: copy-paste the EXACT value you want to attack (e.g. 1426).")
        print("Add one per line. Press Enter on an empty line when you're done.")
        targets = []
        while True:
            t = input("  value to attack (Enter when done)> ").strip()
            if not t:
                break
            targets.append(t)
        mq = query
        mb = body
        for t in targets:
            if mq and t in mq:
                mq = mq.replace(t, f"{MARK}{t}{MARK}", 1)
            elif t in mb:
                mb = mb.replace(t, f"{MARK}{t}{MARK}", 1)
            else:
                print(f"  [!] '{t}' not found in query or body")
        query_marked_final = mq
        body_marked_final = mb
        break

    # 3. tokenize (global marker order: query first, then body)
    if query_marked_final:
        q_tokens, q_orig = tokenize(query_marked_final, 0)
        path_tokens = [("lit", base_path + "?")] + q_tokens
    else:
        q_orig = []
        path_tokens = [("lit", base_path)]
    b_tokens, b_orig = tokenize(body_marked_final or "", len(q_orig))
    originals = q_orig + b_orig
    n_markers = len(originals)
    if n_markers == 0:
        sys.exit("No payload positions marked — nothing to attack.")

    # 4. attack type
    print(f"\n({n_markers} spot(s) marked)")
    attack = choose_attack(n_markers)

    # 5. payloads
    if attack in ("sniper", "battering"):
        payload_sets = [get_payload_list()]
    else:
        payload_sets = [get_payload_list(f"for position {i}") for i in range(n_markers)]

    jobs = make_jobs(attack, n_markers, originals, payload_sets)
    if len(jobs) > 200000:
        if not ask_yes(f"That is {len(jobs):,} requests. Continue?", False):
            sys.exit("Aborted.")
    # How many chars of each response body to keep for the side panel + search.
    # Keep this generous: the difference between a "wrong" and a "correct" page
    # often sits a few KB into the body, and truncating it away makes every row
    # look identical. Duplicate bodies are de-duplicated at report time, and a
    # global size budget (in write_report) is the real safety net.
    body_cap = 20000

    # 6. runtime knobs
    print("\n--- speed & detection (just press Enter to accept the defaults) ---")
    concurrency = ask_int("how many requests at once", 15)
    rate = ask("cap speed to N requests/sec? (Enter = as fast as possible)", "")
    rate = float(rate) if rate else None
    grep = ask("flag responses containing this text? e.g. Congratulations (Enter = skip)", "")
    grep_rx = re.compile(re.escape(grep), re.IGNORECASE) if grep else None

    # optional: route through Burp (or any) proxy so requests show up there
    print("\nProxy: PyIntruder connects DIRECTLY to the target — it does NOT use")
    print("Firefox / FoxyProxy. You can optionally send its traffic THROUGH Burp")
    print("so every request also appears in Burp's HTTP history.")
    proxy = ask("proxy URL (Enter = direct, or http://127.0.0.1:8080 for Burp)", "") or None

    # 7. optional refresh / re-login
    refresh = None
    trigger_codes = set()
    trigger_rx = None
    if ask_yes("\nEnable session re-login/refresh? (needed if the app logs you out)", False):
        print("\nProvide the refresh request sequence (e.g. GET /login, POST /login, GET /2fa).")
        print("Separate multiple requests with a line '---'. Use {{NAME}} placeholders.")
        seq_raw = read_block("Paste refresh sequence:")
        refresh_reqs = [b.strip() for b in seq_raw.split("\n---\n") if b.strip()]
        print("\nExtractors pull tokens from each response for later use.")
        print("Format:  NAME = regex-with-one-group   (e.g. CSRF = name=\"csrf\" value=\"([^\"]+)\")")
        print("One per line, blank to finish.")
        print("(If you don't need token extraction, just press Enter to skip.)")
        extractors = []
        while True:
            line = input("  extractor (Enter to skip / finish)> ").strip()
            if not line:
                break
            if "=" in line:
                name, rx = line.split("=", 1)
                extractors.append((name.strip(), re.compile(rx.strip())))
        codes = ask("trigger status codes (comma) meaning 'logged out'", "302")
        trigger_codes = {int(c) for c in codes.split(",") if c.strip().isdigit()}
        trg = ask("trigger body regex (blank = none)", "")
        trigger_rx = re.compile(trg) if trg else None
        refresh = Refresh(refresh_reqs, extractors, req["headers"].get("Cookie", ""))

    default_out = str(Path("results") / f"pyintruder_results_{time.strftime('%Y%m%d-%H%M%S')}.html")
    out = ask("output HTML file", default_out)

    return {
        "method": req["method"], "host": req["host"], "scheme": scheme,
        "headers": req["headers"], "base_cookie": req["headers"].get("Cookie", ""),
        "path_tokens": path_tokens, "body_tokens": b_tokens,
        "jobs": jobs, "attack": attack,
        "concurrency": concurrency, "rate": rate, "timeout": 20.0,
        "http2": True, "insecure": "--insecure" in sys.argv, "proxy": proxy,
        "body_cap": body_cap,
        "grep_rx": grep_rx, "refresh": refresh,
        "trigger_codes": trigger_codes, "trigger_rx": trigger_rx,
        "out": out,
    }


def main():
    # argparse only for help; real config is interactive
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        print("Usage: python3 pyintruder.py [--request FILE] [--scheme https|http] [--insecure]")
        return
    cfg = build_config()
    results, elapsed = asyncio.run(run_attack(cfg))
    meta = (f"target: {cfg['scheme']}://{cfg['host']} | {cfg['method']} | "
            f"attack: {cfg['attack']} | requests: {len(results)} | {elapsed:.1f}s")
    req_ctx = {
        "method": cfg["method"], "host": cfg["host"], "scheme": cfg["scheme"],
        "httpver": "2" if cfg["http2"] else "1.1",
        "headers": [[k, v] for k, v in cfg["headers"].items()
                    if k.lower() not in _DROP_HEADERS and k.lower() != "cookie"],
    }
    write_report(results, meta, cfg["out"], req_ctx)
    print(f"[+] Report written to {cfg['out']}")
    try:
        webbrowser.open(f"file://{Path(cfg['out']).resolve()}")
    except Exception:
        pass


if __name__ == "__main__":
    main()
