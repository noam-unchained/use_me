#!/usr/bin/env python3
# =====================================================================
#  xss_lab.py  —  LOCAL XSS practice target (reflection contexts)
#  Point pyintruder at one endpoint, mark the value, load xss.txt, grep = xq9z.
#  A payload "works" when the canary reflects with its < > " ' INTACT (unencoded)
#  in that context — then it would execute in a real browser.
#
#  SAFETY: binds to 127.0.0.1 ONLY. Ctrl-C to stop.
#  Run:  python3 xss_lab.py         (port 8000)
#        python3 xss_lab.py 8123    (custom port)
# =====================================================================
import http.server, socketserver, urllib.parse, html, re, sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
CANARY = "xq9z"

INDEX = f"""<h1>xss_lab</h1>
<p>Mark the value, load <b>xss.txt</b>, set grep to <b>{CANARY}</b>. A hit means the
canary reflected; check the response to see if &lt; &gt; " ' survived UNENCODED = injectable.</p>
<ul>
<li><b>HTML text</b> &nbsp; /reflect?q=test &nbsp;(raw reflect between tags)</li>
<li><b>Attribute "..."</b> &nbsp; /attr?q=test &nbsp;(needs "&gt; breakout OR "onmouseover=" style)</li>
<li><b>Attribute '...'</b> &nbsp; /attr1?q=test &nbsp;(single-quote context)</li>
<li><b>JS string</b> &nbsp; /js?q=test &nbsp;(inside &lt;script&gt;var s="..."; needs ";alert(1)//)</li>
<li><b>href</b> &nbsp; /href?q=test &nbsp;(javascript: scheme)</li>
<li><b>Filtered</b> &nbsp; /filter?q=test &nbsp;(strips "script" — use &lt;svg&gt;/&lt;img&gt; bypasses)</li>
<li><b>Safe (encoded)</b> &nbsp; /safe?q=test &nbsp;(canary reflects but everything is encoded = NOT injectable)</li>
</ul>
"""

class H(http.server.BaseHTTPRequestHandler):
    def reply(self, body, code=200):
        b = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        q = qs.get("q", [""])[0]
        p = u.path

        if p == "/":
            return self.reply(INDEX)
        if p == "/reflect":                                   # HTML text context (raw)
            return self.reply(f"<h1>Search</h1><p>You searched: {q}</p>")
        if p == "/attr":                                      # double-quoted attribute
            return self.reply(f'<form><input type="text" value="{q}"></form>')
        if p == "/attr1":                                     # single-quoted attribute
            return self.reply(f"<form><input type='text' value='{q}'></form>")
        if p == "/js":                                        # inside a JS string
            return self.reply(f'<script>var s = "{q}"; console.log(s);</script><p>ok</p>')
        if p == "/href":                                      # href / URL context
            return self.reply(f'<a href="{q}">your link</a>')
        if p == "/filter":                                    # strips the word "script", then raw
            return self.reply(f"<p>{re.sub('script', '', q, flags=re.I)}</p>")
        if p == "/safe":                                      # HTML-encoded (not vulnerable)
            return self.reply(f"<p>You searched: {html.escape(q)}</p>")
        return self.reply("not found", code=404)

    def log_message(self, *a):
        pass

class Threaded(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    with Threaded(("127.0.0.1", PORT), H) as srv:
        print(f"""
  xss_lab running:  http://127.0.0.1:{PORT}/     (127.0.0.1 only — Ctrl-C to stop)

  Try with pyintruder (mark the value, load xss.txt, grep = {CANARY}):
    HTML text   http://127.0.0.1:{PORT}/reflect?q=FUZZ
    attribute   http://127.0.0.1:{PORT}/attr?q=FUZZ
    attr '..'   http://127.0.0.1:{PORT}/attr1?q=FUZZ
    JS string   http://127.0.0.1:{PORT}/js?q=FUZZ
    href        http://127.0.0.1:{PORT}/href?q=FUZZ
    filtered    http://127.0.0.1:{PORT}/filter?q=FUZZ   (script-word stripped)
    safe        http://127.0.0.1:{PORT}/safe?q=FUZZ     (encoded = should NOT be injectable)

  A row is a real hit only if the canary reflects with < > " ' UNENCODED in that context.
""")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\n  stopped.")
