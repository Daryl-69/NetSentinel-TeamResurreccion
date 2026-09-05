#!/usr/bin/env bash
# zeekify.sh -- turn the captured pcaps into the Zeek logs train_real.py eats.
#
# Run this in WSL (Ubuntu) or any Linux box that can see the capture folder.
# From Windows, D:\capture is /mnt/d/capture inside WSL.
#
#   ./zeekify.sh /mnt/d/capture /mnt/d/capture-zeek
#
# Then, back on Windows:
#   .\.venv\Scripts\python.exe train_real.py --data D:\capture-zeek --seeds 3
#
# It is INCREMENTAL: each pcap gets its own output folder and is skipped if
# already processed, so run it nightly while the capture keeps going. That
# matters -- you do not want to discover on the 18th that Zeek chokes on your
# files.

set -euo pipefail

SRC="${1:-/mnt/d/capture}"
DST="${2:-/mnt/d/capture-zeek}"

if ! command -v zeek >/dev/null 2>&1; then
    cat <<'EOF'
zeek not found.

Ubuntu / WSL:
    sudo apt update && sudo apt install -y zeek
    export PATH=$PATH:/opt/zeek/bin        # if apt put it there

If apt has no zeek package, use the official repo (one paste):
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
      | sudo tee /etc/apt/sources.list.d/zeek.list
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
      | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/zeek.gpg >/dev/null
    sudo apt update && sudo apt install -y zeek

No WSL? Docker works and needs nothing installed:
    docker run --rm -v D:\capture:/pcap -v D:\capture-zeek:/out -w /out \
        zeek/zeek:latest sh -c 'for f in /pcap/*.pcap*; do
            d=/out/$(basename "$f" | sed "s/\.pcap.*//"); mkdir -p "$d";
            (cd "$d" && zeek -C -r "$f" local); done'
EOF
    exit 1
fi

[ -d "$SRC" ] || { echo "no such folder: $SRC"; exit 1; }
mkdir -p "$DST"

shopt -s nullglob
files=("$SRC"/*.pcap "$SRC"/*.pcapng "$SRC"/*.pcap.gz)
if [ ${#files[@]} -eq 0 ]; then
    echo "no pcap files under $SRC -- is the capture actually running?"
    exit 1
fi

done_n=0; skip_n=0; fail_n=0
for f in "${files[@]}"; do
    base=$(basename "$f"); base="${base%%.pcap*}"
    out="$DST/$base"
    if [ -f "$out/conn.log" ] || [ -f "$out/conn.log.gz" ]; then
        skip_n=$((skip_n + 1)); continue
    fi
    mkdir -p "$out"
    # -C ignores checksum errors, which are normal with NIC offload and would
    # otherwise make Zeek drop most of the traffic silently.
    if (cd "$out" && zeek -C -r "$f" local 2>zeek.err); then
        done_n=$((done_n + 1))
        printf '  ok   %s\n' "$base"
    else
        fail_n=$((fail_n + 1))
        printf '  FAIL %s  (see %s/zeek.err)\n' "$base" "$out"
    fi
done

echo
echo "processed $done_n, skipped $skip_n already done, $fail_n failed"

# ---------------------------------------------------------------- merge -----
# Zeek reads ONE pcap at a time, so a 12-day capture becomes ~288 hourly output
# folders. Pointed at that, train_real.py treats every folder as a separate
# capture and every host as 288 different hosts with one hour each -- which
# destroys the multi-day per-host baseline that is the entire point of running
# for 12 days. So concatenate the logs into one directory spanning the whole
# capture. Zeek TSV tolerates this: '#' lines are skipped and '#fields' simply
# re-declares the same columns each time.
MERGED="$DST/_merged"
mkdir -p "$MERGED"
for kind in conn ssl dns http; do
    found=$(find "$DST" -mindepth 2 -name "$kind.log" \
                 -not -path "$MERGED/*" 2>/dev/null | sort)
    [ -z "$found" ] && continue
    : > "$MERGED/$kind.log"
    echo "$found" | while read -r one; do cat "$one" >> "$MERGED/$kind.log"; done
    lines=$(grep -vc '^#' "$MERGED/$kind.log" 2>/dev/null || echo 0)
    printf '  merged %-5s %8s records\n' "$kind" "$lines"
done
echo "  -> $MERGED"

# The single most important sanity check: without ssl.log the Service Category
# Resolver has no hostnames and the whole cross-service hypothesis is untestable
# on this capture. Catch that on day 1, not on the 18th.
ssl_n=$(find "$DST" -name 'ssl.log'  -not -path "$MERGED/*" 2>/dev/null | wc -l)
dns_n=$(find "$DST" -name 'dns.log'  -not -path "$MERGED/*" 2>/dev/null | wc -l)
conn_n=$(find "$DST" -name 'conn.log' -not -path "$MERGED/*" 2>/dev/null | wc -l)
echo "logs: conn=$conn_n  ssl=$ssl_n  dns=$dns_n"
if [ "$ssl_n" -eq 0 ] && [ "$dns_n" -eq 0 ]; then
    echo
    echo ">> NO ssl.log AND NO dns.log. There are no hostnames to resolve, so"
    echo "   every external destination will land in Unknown_External and this"
    echo "   capture CANNOT test the category-sequence idea. Check that the"
    echo "   capture interface is the one carrying real browsing traffic, and"
    echo "   that the snaplen is >=160 bytes."
fi

sni=$(find "$DST" -name 'ssl.log' -not -path "$MERGED/*" -exec awk -F'\t' '!/^#/{print $10}' {} + 2>/dev/null \
      | grep -v '^-$' | sort -u | wc -l)
echo "distinct SNI hostnames so far: $sni"
echo
echo "next:  train_real.py --data $MERGED --seeds 3"
echo
echo "SHARING WITH THE TEAM: rename _merged to your own name (deep, amit, ...)"
echo "and drop every person's folder under one parent, e.g."
echo "    team-capture/deep/{conn,ssl,dns}.log"
echo "    team-capture/amit/{conn,ssl,dns}.log"
echo "then run  train_real.py --data team-capture --seeds 3"
echo "The folder name namespaces the hosts, so two people both sitting on"
echo "192.168.1.5 stay two distinct hosts instead of merging into one."
