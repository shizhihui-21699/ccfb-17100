#!/usr/bin/env bash
# End-to-end demo: run shortlinkd against a live "partner" webserver that
# performs the approve-then-swap attack, and show the service catching it.
#
# Everything runs on loopback, so -allow-private-net is passed to the probe.
# That flag exists for exactly this kind of test; it must never be set in prod.
set -euo pipefail
cd "$(dirname "$0")/.."

PUB=18080
ADM=18081
PARTNER=19090
WORK=$(mktemp -d)
AUDIT="$WORK/audit.log"
SEAL=$(head -c 32 /dev/urandom | base64)

cleanup() { kill "${PUBPID:-}" "${PARTNERPID:-}" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

echo "== building =="
go build -o "$WORK/shortlinkd" ./cmd/shortlinkd

# ---------------------------------------------------------------------------
# A partner site with a stage switch: benign landing page, then phishing kit.
# ---------------------------------------------------------------------------
mkdir -p "$WORK/partner"
cat > "$WORK/partner/landing.html" <<'HTML'
<!doctype html><html><head><title>春季大促</title></head>
<body><h1>满 300 减 50</h1><a href="/shop">立即选购</a>
<script src="/static/analytics.js"></script></body></html>
HTML
cat > "$WORK/partner/evil.html" <<'HTML'
<!doctype html><html><head><title>账户安全验证</title></head>
<body><h1>请重新验证您的银行账户</h1>
<form action="http://127.0.0.1:19091/collect" method="post">
  <input type="text" name="card">
  <input type="password" name="pin">
  <button>验证</button>
</form>
</body></html>
HTML
echo 'window.dataLayer=[]' > "$WORK/partner/analytics.js"
echo -n benign > "$WORK/partner/stage"
echo -n '{"status":"ok"}' > "$WORK/partner/collect"

# Serve either the benign or the evil page depending on the stage file.
cat > "$WORK/switch.py" <<'PY'
import http.server, socketserver, os, sys
stage_file = sys.argv[1]
root = sys.argv[2]
port = int(sys.argv[3])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        stage = open(stage_file).read().strip()
        name = "landing.html" if stage == "benign" else "evil.html"
        try:
            data = open(os.path.join(root, name), "rb").read()
        except FileNotFoundError:
            self.send_error(404); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", port), H) as s:
    s.serve_forever()
PY
python3 "$WORK/switch.py" "$WORK/partner/stage" "$WORK/partner" $PARTNER >/dev/null 2>&1 &
PARTNERPID=$!
sleep 0.6

# ---------------------------------------------------------------------------
# Start the service.
# ---------------------------------------------------------------------------
"$WORK/shortlinkd" \
  -public-addr "127.0.0.1:$PUB" -admin-addr "127.0.0.1:$ADM" \
  -base-url "http://127.0.0.1:$PUB" -self-hosts "s.example.invalid" \
  -allowlist "127.0.0.1" -seal-key "$SEAL" -audit-log "$AUDIT" \
  -allow-private-net -scan-tick 1s -scan-batch 10 >"$WORK/svc.log" 2>&1 &
PUBPID=$!
sleep 1.0

TARGET="http://127.0.0.1:$PARTNER/landing"
api() { curl -sS -H 'Content-Type: application/json' "$@"; }
jget() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

echo
echo "== 1. marketing creates a link to the partner landing page =="
CREATE=$(api -X POST "http://127.0.0.1:$ADM/api/links" \
  -d "{\"target\":\"$TARGET\",\"creator_id\":\"u_mkt_07\",\"creator_name\":\"市场部小李\",\"dept\":\"marketing\",\"campaign\":\"spring-2026\"}")
echo "$CREATE" | python3 -c "
import sys,json
r=json.load(sys.stdin); l=r['link']
print('  short url :', r['short_url'])
print('  status    :', l['status'], '| interstitial:', l['force_interstitial'])
print('  risk      :', l['risk']['level'], l['risk']['score'], '->', ', '.join(x['code'] for x in l['risk']['reasons']))
print('  warning   :', r.get('warning'))"
CODE=$(echo "$CREATE" | jget "['link']['code']")
ID=$(echo "$CREATE" | jget "['link']['id']")

echo
echo "== 2. click before the deep scan finishes: interstitial, not redirect =="
curl -sS -o "$WORK/wall.html" -w "HTTP %{http_code}\n" "http://127.0.0.1:$PUB/$CODE"
grep -o '外部网站' "$WORK/wall.html" | head -1

echo
echo "== 3. wait for patrol to scan + baseline the benign page =="
for i in $(seq 1 20); do
  ST=$(api "http://127.0.0.1:$ADM/api/links/$ID" | jget "['status']")
  [ "$ST" = "active" ] && break
  sleep 0.5
done
echo "link status: $ST"

echo
echo "== 4. THE ATTACK: partner swaps in a credential-harvesting page =="
echo -n evil > "$WORK/partner/stage"
scan() { api -X POST "http://127.0.0.1:$ADM/api/links/$ID/scan"; }
scan >/dev/null  # trigger one patrol pass immediately
sleep 1
STATE=$(api "http://127.0.0.1:$ADM/api/links/$ID")
echo "$STATE" | python3 -c "
import sys,json
l=json.load(sys.stdin)
print('  status :', l['status'])
print('  reason :', l.get('quarantine_reason'))
print('  risk   :', l['risk']['level'], l['risk']['score'], '->', ', '.join(x['code'] for x in l['risk']['reasons']))"

echo
echo "== 5. links clicked now are refused =="
curl -sS -o "$WORK/blocked.html" -w "HTTP %{http_code}\n" "http://127.0.0.1:$PUB/$CODE"
grep -o '拦截' "$WORK/blocked.html" | head -1

echo
echo "== 6. one-click containment: revoke every link to that domain =="
api -X POST "http://127.0.0.1:$ADM/api/revoke/domain" \
  -d "{\"domain\":\"127.0.0.1\",\"actor\":\"sec_ops_zhang\",\"reason\":\"partner domain compromised, user reports\"}" \
  | python3 -m json.tool

echo
echo "== 7. trace back: who created it, and the tamper-evident trail =="
api "http://127.0.0.1:$ADM/api/links/$ID/audit" \
  | python3 -c "
import sys,json
ev=json.load(sys.stdin)['events']
for e in ev: print(f\"  #{e['seq']:<2} {e['action']:<16} by {e['actor']:<16} {e.get('meta','')}\")"
echo -n "audit chain: "
api "http://127.0.0.1:$ADM/api/audit/verify" | python3 -m json.tool

echo
echo "== 8. a lookalike domain is refused at creation =="
api -X POST "http://127.0.0.1:$ADM/api/links" \
  -d '{"target":"http://secure-login-verify.evil.top/","creator_id":"u_mkt_07"}' \
  -w "\nHTTP %{http_code}\n"

echo
echo "demo finished"
