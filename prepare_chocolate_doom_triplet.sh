#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 ./chocolate-doom/doom1.wad ./chocolate-doom/chocolate-doom.js ./chocolate-doom/chocolate-doom.wasm" >&2
  exit 1
fi

WAD_PATH="$1"
JS_PATH="$2"
WASM_PATH="$3"

for f in "$WAD_PATH" "$JS_PATH" "$WASM_PATH"; do
  if [ ! -f "$f" ]; then
    echo "Missing file: $f" >&2
    exit 1
  fi
done

for bin in sha256sum ipfs mktorrent; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "Required binary not found in PATH: $bin" >&2
    exit 1
  fi
done

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

add_ipfs() {
  # Use CIDv1; adjust if you have stricter policy
  ipfs add --cid-version=1 -Q "$1"
}

# Create a .torrent file for a single payload using mktorrent.
# The .torrent is written next to the payload ("file" -> "file.torrent").
make_torrent() {
  local payload="$1"
  local torrent="${payload}.torrent"
  # Only rebuild if missing, so reruns are cheap and deterministic.
  if [ ! -f "$torrent" ]; then
    # Use the TRACKERS list below as announce URLs.
    # Piece size: let mktorrent decide automatically.
    local args=("-q" "-o" "$torrent")
    local tr
    for tr in "${TRACKERS[@]}"; do
      args+=("-a" "$tr")
    done
    # Discard mktorrent stdout; we only care about the file it writes.
    mktorrent "${args[@]}" "$payload" >/dev/null
  fi
  printf '%s\n' "$torrent"
}

# Extract the BitTorrent info hash (btih) from an existing .torrent file.
# Uses sha1 over the bencoded "info" dictionary.
torrent_btih() {
  local torrent="$1"
  # python3 is ubiquitous on this system; if you prefer another tool
  # we can swap this implementation.
  python3 - "$torrent" << 'PYEOF'
import sys, hashlib

path = sys.argv[1]
with open(path, 'rb') as f:
    data = f.read()

# Naive bencode parsing to isolate the top-level "info" dict.
# This assumes a standard torrent structure: d ... 4:infod ... ee
marker = b'4:info'
idx = data.find(marker)
if idx == -1:
    raise SystemExit('no info dict in torrent')

i = idx + len(marker)
depth = 0
start = i
while i < len(data):
    c = data[i:i+1]
    if c == b'd' or c == b'l':
        depth += 1
        i += 1
    elif c == b'e':
        depth -= 1
        i += 1
        if depth == 0:
            end = i
            break
    elif c == b'i':
        # integer: i<digits>e
        i = data.index(b'e', i) + 1
    elif b'0' <= c <= b'9':
        # string: <len>:<bytes>
        j = data.index(b':', i)
        ln = int(data[i:j])
        i = j + 1 + ln
    else:
        raise SystemExit('invalid bencode structure')
else:
    raise SystemExit('unterminated info dict')

info = data[start:end]
print(hashlib.sha1(info).hexdigest())
PYEOF
}

TRACKERS=(
  "udp://tracker.opentrackr.org:1337/announce"
  "udp://tracker.torrent.eu.org:451/announce"
  "udp://open.stealth.si:80/announce"
  "udp://tracker.qu.ax:6969/announce"
)

build_magnet() {
  local cid="$1"
  local dn="$2"
  local btih="$3"
  local magnet="magnet:?xt=urn:btih:${btih}&xt=urn:ipfs:${cid}&dn=${dn}&ws=https://ipfs.ness.cx/ipfs/${cid}"
  for tr in "${TRACKERS[@]}"; do
    magnet+="&tr=${tr}"
  done
  printf '%s\n' "$magnet"
}

echo ">> Computing SHA-256 digests..."
WAD_SHA256="$(hash_file "$WAD_PATH")"
JS_SHA256="$(hash_file "$JS_PATH")"
WASM_SHA256="$(hash_file "$WASM_PATH")"

echo "WAD  sha256: $WAD_SHA256"
echo "JS   sha256: $JS_SHA256"
echo "WASM sha256: $WASM_SHA256"
echo

echo ">> Adding files to IPFS..."
WAD_CID="$(add_ipfs "$WAD_PATH")"
JS_CID="$(add_ipfs "$JS_PATH")"
WASM_CID="$(add_ipfs "$WASM_PATH")"

echo "WAD  CID: $WAD_CID"
echo "JS   CID: $JS_CID"
echo "WASM CID: $WASM_CID"
echo

echo "================ EmerDNS mappings (logical names) ================"
echo "doomwad.private.ness  ->  $WAD_CID"
echo "doomjs.private.ness   ->  $JS_CID"
echo "doomwasm.private.ness ->  $WASM_CID"
echo
echo "# In EmerDNS/NVS you will store those CIDs under the appropriate d:* records."
echo

echo "================ IPFS URLs via ipfs.ness.cx ======================"
echo "WAD  URL: https://ipfs.ness.cx/ipfs/$WAD_CID"
echo "JS   URL: https://ipfs.ness.cx/ipfs/$JS_CID"
echo "WASM URL: https://ipfs.ness.cx/ipfs/$WASM_CID"
echo

echo "================ Magnet URIs (3-way backup) ======================"
echo ">> Generating .torrent files and dual IPFS+BitTorrent magnets..."

WAD_TORRENT="$(make_torrent "$WAD_PATH")"
JS_TORRENT="$(make_torrent "$JS_PATH")"
WASM_TORRENT="$(make_torrent "$WASM_PATH")"

WAD_BTIH="$(torrent_btih "$WAD_TORRENT")"
JS_BTIH="$(torrent_btih "$JS_TORRENT")"
WASM_BTIH="$(torrent_btih "$WASM_TORRENT")"

echo "WAD  torrent: $WAD_TORRENT"
echo "JS   torrent: $JS_TORRENT"
echo "WASM torrent: $WASM_TORRENT"
echo

echo "WAD  magnet:"
echo "  $(build_magnet "$WAD_CID" "doom-wad" "$WAD_BTIH")"
echo
echo "JS   magnet:"
echo "  $(build_magnet "$JS_CID" "doom-js" "$JS_BTIH")"
echo
echo "WASM magnet:"
echo "  $(build_magnet "$WASM_CID" "doom-wasm" "$WASM_BTIH")"
echo

echo "================ NAME_UPDATE / NAME_NEW payloads =================="
echo "# Example EmerDNS/NVS records you may want to apply manually:"
echo "NAME_UPDATE doomwad.private.ness  $WAD_CID  ; IPFS CID for WAD"
echo "NAME_UPDATE doomjs.private.ness   $JS_CID   ; IPFS CID for JS engine"
echo "NAME_UPDATE doomwasm.private.ness $WASM_CID ; IPFS CID for WASM core"
echo "# Optionally store associated magnets (dual IPFS+BitTorrent):"
echo "NAME_NEW magnet:doom-wad   $(build_magnet "$WAD_CID" "doom-wad" "$WAD_BTIH")"
echo "NAME_NEW magnet:doom-js    $(build_magnet "$JS_CID" "doom-js" "$JS_BTIH")"
echo "NAME_NEW magnet:doom-wasm  $(build_magnet "$WASM_CID" "doom-wasm" "$WASM_BTIH")"
echo

echo "================ JS constants for production_doom.html =========="
cat <<EOF
// Expected digests for integrity enforcement (SHA-256 hex)
const EXPECTED_WAD_SHA256  = "$WAD_SHA256";
const EXPECTED_JS_SHA256   = "$JS_SHA256";
const EXPECTED_WASM_SHA256 = "$WASM_SHA256";

// EmerDNS names (kept as requested)
const WAD_DOMAIN_NAME  = "doomwad.private.ness";
const JS_DOMAIN_NAME   = "doomjs.private.ness";
const WASM_DOMAIN_NAME = "doomwasm.private.ness";
TRACKERS=(
  "udp://tracker.opentrackr.org:1337/announce"
  "udp://tracker.torrent.eu.org:451/announce"
  "udp://open.stealth.si:80/announce"
  "udp://tracker.qu.ax:6969/announce"
)

build_magnet() {
  local cid="$1"
  local dn="$2"
  local magnet="magnet:?xt=urn:ipfs:\${cid}&dn=\${dn}&ws=https://ipfs.ness.cx/ipfs/\${cid}"
  for tr in "\${TRACKERS[@]}"; do
    magnet+="&tr=\${tr}"
  done
  printf '%s\n' "\$magnet"
}

EOF
echo
echo "Done. Use the above constants and mappings in production_doom.html."
