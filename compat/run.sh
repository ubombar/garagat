#!/usr/bin/env bash
# Runs caracal and garagat on the same probes in the same container, one
# after the other, with tcpdump capturing everything on eth0.
set -euo pipefail
log() { echo "== $*" >&2; }

cd /work
GW=$(ip route | awk '/default/ {print $3}')
MAC=$(cat /sys/class/net/eth0/address | tr -d :)
{
  for ttl in 1 2 3; do echo "$GW,24000,0,$ttl,icmp"; echo "$GW,24001,33434,$ttl,udp"; done
  for ttl in $(seq 1 10); do echo "8.8.8.8,24000,0,$ttl,icmp"; done
  for ttl in $(seq 1 6); do echo "1.1.1.1,24002,33434,$ttl,udp"; done
  echo "134743044,25000,0,9,icmp"
  echo "::ffff:9.9.9.9,26000,0,7,icmp"
  echo "9.9.9.9,26001,33435,5,udp,0,1000"
  echo "not a probe"
} > probes.csv
log "$(grep -c . probes.csv) lines, gateway $GW"

for tool in caracal garagat; do
  log "running $tool"
  tcpdump -i eth0 -U -w $tool.pcap 2>/dev/null &
  TD=$!
  sleep 1
  $tool --caracal-id 4242 -r 50 -W 2 --meta-round 1 < probes.csv > $tool.csv 2> $tool.log
  sleep 1
  kill $TD; wait $TD || true
done

log "probes on the wire"
/work/compare caracal.pcap "$MAC" garagat.pcap "$MAC" || true

log "CSV header"
diff <(head -1 caracal.csv) <(head -1 garagat.csv) && echo identical

# Drop capture_timestamp (1) and rtt (16), which depend on timing.
norm() { tail -n +2 "$1" | awk -F, -v OFS=, '{ $1=""; $(NF-1)=""; print }' | sort; }
log "CSV rows (without capture_timestamp and rtt)"
echo "caracal $(($(wc -l < caracal.csv)-1)) rows, garagat $(($(wc -l < garagat.csv)-1)) rows"
diff <(norm caracal.csv) <(norm garagat.csv) && echo "all rows identical"

log "rtt (tenths of ms) per tool"
for t in caracal garagat; do echo "$t: $(tail -n +2 $t.csv | awk -F, '{print $(NF-1)}' | sort -n | tr '\n' ' ')"; done

log "statistics"
grep -hE "probes_read|packets_received=" caracal.log garagat.log | sed 's/^\[[^]]*\] //'
log "invalid-line handling"
grep -h "not a probe" caracal.log garagat.log | sed 's/^\[[^]]*\] //'
