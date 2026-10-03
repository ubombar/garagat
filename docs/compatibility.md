# Compatibility with caracal

This page records how garagat was compared with caracal and what the comparison showed. The goal is that garagat can replace caracal in an existing pipeline: same probes on the wire, same CSV output.

## Versions

| Tool | Version |
| --- | --- |
| caracal | commit `f2b2a5f` ("fix: pass capture_timestamp as-is without microsecond conversion (#66)"), built from source with its own Dockerfile (Ubuntu 22.04, Release build) |
| garagat | commit with this document, built with `CGO_ENABLED=0` |

The published `ghcr.io/dioptra-io/caracal` image could not be pulled at the time (its manifest was missing), so caracal was built from a local checkout.

## Method

Both tools ran in the same Linux container (Docker on colima, Linux kernel, `eth0` behind Docker's NAT), one after the other, with the same input and the same options:

```bash
<tool> --caracal-id 4242 -r 50 -W 2 --meta-round 1 < probes.csv > <tool>.csv
```

tcpdump recorded all traffic on `eth0` during each run. The probe file had 26 lines:

- ICMP and UDP probes to the container's gateway at TTL 1 to 3;
- ICMP probes to 8.8.8.8 at TTL 1 to 10 and UDP probes to 1.1.1.1 at TTL 1 to 6;
- one destination written as a decimal integer (`134743044`) and one as an IPv4-mapped address (`::ffff:9.9.9.9`);
- one probe with the optional `flow_label` and `wait_us` columns;
- one invalid line.

Three things were compared:

1. **Probes on the wire.** `compat/main.go` reads both captures and compares every probe packet sent by the container, byte for byte from the IP header. The fields that hold the send time are cleared first: the ICMP sequence number or UDP checksum, and the two payload bytes that keep the checksum valid.
2. **CSV output.** The header, then every row with `capture_timestamp` and `rtt` removed (they depend on timing), sorted.
3. **Logs.** The final statistics and the handling of the invalid line.

## Results

| Check | caracal | garagat | Result |
| --- | --- | --- | --- |
| Probes sent | 25 | 25 | 25/25 identical outside the timestamp fields (IP ID, TTL, lengths, ports, flow ID, checksums) |
| CSV header | | | identical |
| Reply rows | 19 | 19 | all identical except `capture_timestamp` and `rtt` |
| RTT (tenths of ms) | 0 to 3 | 0 to 4 | same range |
| Statistics | read 25, sent 25, received 19, invalid 0, 4 distinct reply sources | same | identical |
| Invalid line | logged and skipped | logged and skipped | same behaviour, different error text |

The replies were ICMP time exceeded from the gateway, ICMP echo replies and ICMP port unreachable messages. Since the IP ID matches, garagat and caracal validate each other's replies with the same `--caracal-id`.

## Limits

- IPv4 only: the Docker network had no IPv6. IPv6 is covered by the unit tests, which parse caracal's IPv6 captures and rebuild its IPv6 probes byte for byte.
- No real Internet path: colima's NAT answers probes to Internet addresses itself, so no multi-hop time exceeded or MPLS replies were seen live. MPLS parsing is covered by the unit tests on caracal's captures.
- One run, at 50 probes per second.

## Reproducing

```bash
docker build -t caracal-local /path/to/caracal
make compare
```

`compat/run.sh` writes the probe file, runs both tools with tcpdump, and prints the comparison.
