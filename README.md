# garagat

[![CI](https://github.com/ubombar/garagat/actions/workflows/ci.yml/badge.svg)](https://github.com/ubombar/garagat/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ubombar/garagat.svg)](https://pkg.go.dev/github.com/ubombar/garagat)

garagat is a stateless ICMP/UDP, IPv4/IPv6 Paris traceroute and ping engine written in pure Go. It is a port of [caracal](https://github.com/dioptra-io/caracal) (C++) and [caracat](https://github.com/dioptra-io/caracat) (Rust) from the [Dioptra group](https://dioptra.io): it encodes probes the same way, reads the same input and writes the same CSV output, so it can replace caracal in an existing pipeline.

It has no cgo and no libpcap dependency. Packets are sent and captured with `AF_PACKET` sockets on Linux and BPF devices (`/dev/bpf`) on macOS and FreeBSD, filtered in the kernel with classic BPF programs generated in Go. A `CGO_ENABLED=0` build gives a single static binary.

## Quickstart

```bash
go install github.com/ubombar/garagat/cmd/garagat@latest
```

Probe the Google DNS servers at TTL 32:

```bash
cat > probes.csv <<EOF
8.8.8.8,24000,33434,32,icmp
8.8.4.4,24000,33434,32,icmp
2001:4860:4860::8888,24000,33434,32,icmp6
2001:4860:4860::8844,24000,33434,32,icmp6
EOF
sudo garagat < probes.csv > replies.csv
```

Sending raw packets needs privileges: root, or `CAP_NET_RAW` on Linux (`sudo setcap cap_net_raw+ep $(which garagat)`), or read/write access to `/dev/bpf*` on macOS and FreeBSD.

With Docker:

```bash
docker build -t garagat .
docker run --rm -i garagat < probes.csv > replies.csv
```

## Input format

garagat reads one probe per line on the standard input:

```csv
dst_addr,src_port,dst_port,ttl,protocol[,flow_label[,wait_us]]
```

- `dst_addr` is an IPv4 address in dotted notation (`8.8.8.8`), an IPv4 address as a decimal integer (`134743044`), an IPv4-mapped IPv6 address (`::ffff:8.8.8.8`) or an IPv6 address.
- `src_port` and `dst_port` are between 0 and 65535. For UDP probes they are the UDP ports. For ICMP probes the source port is encoded in the ICMP checksum and identifier, which varies the flow ID, and the destination port is ignored.
- `ttl` is between 0 and 255.
- `protocol` is `icmp`, `icmp6` or `udp`.
- `flow_label` (optional) is the IPv6 flow label.
- `wait_us` (optional) is a number of microseconds to wait after sending the probe.

Invalid lines are logged and skipped.

## Output format

Replies are written in CSV on the standard output, logs go to the standard error:

```csv
capture_timestamp,probe_protocol,probe_src_addr,probe_dst_addr,probe_src_port,probe_dst_port,probe_ttl,quoted_ttl,reply_src_addr,reply_protocol,reply_icmp_type,reply_icmp_code,reply_ttl,reply_size,reply_mpls_labels,rtt,round
```

| Column | Description |
| --- | --- |
| `capture_timestamp` | Capture time of the reply in microseconds since the Unix epoch. |
| `probe_protocol` | IP protocol number of the probe (1, 17 or 58). |
| `probe_src_addr` | Source address of the probe (the destination of the reply), as IPv6 or IPv4-mapped IPv6. |
| `probe_dst_addr` | Destination of the probe, quoted in the ICMP reply. For echo replies this is the reply source. |
| `probe_src_port` | UDP source port, or ICMP identifier, of the probe. |
| `probe_dst_port` | UDP destination port of the probe (0 for ICMP). |
| `probe_ttl` | TTL of the probe, decoded from the probe payload length. |
| `quoted_ttl` | TTL of the probe when it reached the replying host. |
| `reply_src_addr` | Source address of the reply. |
| `reply_protocol` | IP protocol number of the reply (1 or 58). |
| `reply_icmp_type`, `reply_icmp_code` | ICMP type and code of the reply. |
| `reply_ttl` | TTL of the reply. |
| `reply_size` | IPv4 total length, or IPv6 payload length, of the reply. |
| `reply_mpls_labels` | MPLS label stack from the ICMP extensions (RFC 4950), as `"[(label,exp,bottom_of_stack,ttl),...]"`. |
| `rtt` | Round-trip time in tenths of milliseconds, from the timestamp encoded in the probe. |
| `round` | Value of `--meta-round` (default `1`). |

Example with SQLite:

```bash
echo "8.8.8.8,24000,33434,64,icmp" | sudo garagat | sqlite3 garagat.db ".import --csv /dev/stdin replies"
```

## Options

```text
  -h, --help                                  Show this message
      --version                               Show the version and exit
  -r, --probing-rate int                      Probing rate in packets per second (default 100)
  -z, --interface string                      Interface from which to send the packets (default: interface of the default route)
  -B, --batch-size int                        Number of probes to send before calling the rate limiter (default 128)
  -L, --log-level string                      Minimum log level (trace, debug, info, warning, error, fatal) (default "info")
  -N, --n-packets int                         Number of packets to send per probe (default 1)
  -P, --max-probes int                        Maximum number of probes to send (unlimited by default)
      --source-address-v4 string              Specify the IPv4 source address to use in the packets (if probing in v4)
      --source-address-v6 string              Specify the IPv6 source address to use in the packets (if probing in v6)
      --gateway-mac-v4 string                 MAC address of the IPv4 gateway (resolved with ARP by default)
      --gateway-mac-v6 string                 MAC address of the IPv6 gateway (resolved with NDP by default)
  -W, --sniffer-wait-time int                 Time in seconds to wait after sending the probes to stop the sniffer (default 1)
      --rate-limiting-method string           Method to use to limit the packets rate (auto, active, sleep, none) (default "auto")
      --filter-from-prefix-file-excl string   Do not send probes to prefixes specified in file (deny list)
      --filter-from-prefix-file-incl string   Do not send probes to prefixes *not* specified in file (allow list)
      --filter-min-ttl int                    Do not send probes with ttl < min_ttl
      --filter-max-ttl int                    Do not send probes with ttl > max_ttl
      --caracal-id int                        Identifier encoded in the probes (random by default)
      --meta-round string                     Value of the round column in the CSV output
      --no-integrity-check                    Do not check that replies match valid probes
      --output-file-pcap string               Write every captured packet (including invalid replies) to this pcap file
      --dry-run                               Build the probes but do not send them
```

Prefix files contain one prefix per line (`192.0.2.0/24`, `2001:db8::/32`, `::ffff:192.0.2.0/120` or a single address); lines starting with `#` are ignored. On SIGINT or SIGTERM garagat stops reading probes, waits `--sniffer-wait-time` for the last replies and flushes its output.

## How probes are encoded

garagat is stateless: everything needed to match a reply to its probe is carried in the probe and quoted back by the router.

- The flow ID (Paris traceroute) is the UDP ports, or the ICMP checksum for ICMP probes. The ICMP identifier is set to the same value and two payload bytes are tweaked so that the checksum stays valid.
- The TTL is encoded in the payload length (`payload = ttl + 2 bytes`), since routers overwrite the TTL field.
- The send time, in tenths of milliseconds modulo 65535, is in the ICMP sequence number or in the UDP checksum (again kept valid by the payload bytes). The RTT is computed from the capture time of the reply.
- For IPv4 the IP ID field holds a checksum of the caracal ID, destination address, source port and TTL. Time exceeded and destination unreachable replies whose quoted IP ID does not match are dropped, unless `--no-integrity-check` is given. Dropped packets are still written to `--output-file-pcap`.

The probes are byte-for-byte identical to caracal's for the same inputs (this is tested against the packets in caracal's test captures), including the IP ID, so replies to garagat and caracal probes can be validated by either tool with the same `--caracal-id`.

## Library

garagat is also a library. The packages are:

| Package | Contents |
| --- | --- |
| [`garagat`](https://pkg.go.dev/github.com/ubombar/garagat) | Probe and reply models, CSV formats, packet builder, reply parser, checksums, timestamps, rate limiter, longest-prefix-match set, simulated replies. |
| [`link`](https://pkg.go.dev/github.com/ubombar/garagat/link) | Raw packet I/O (AF_PACKET, BPF), kernel filters, and an in-memory simulated link for tests. |
| [`neighbors`](https://pkg.go.dev/github.com/ubombar/garagat/neighbors) | Default routes, interface addresses, ARP and NDP resolution. |
| [`prober`](https://pkg.go.dev/github.com/ubombar/garagat/prober) | The probing loop used by the CLI: configuration, sender, sniffer, statistics. |
| [`pcapfile`](https://pkg.go.dev/github.com/ubombar/garagat/pcapfile) | pcap file reader and writer. |

```go
cfg := prober.DefaultConfig()
cfg.ProbingRate = 10_000
cfg.Output = os.Stdout
stats, err := prober.ProbeReader(ctx, cfg, strings.NewReader("8.8.8.8,24000,33434,8,udp\n"))
```

To build probes and parse replies yourself:

```go
b := &garagat.ProbeBuilder{L2: garagat.L2None, SrcIPv4: src, CaracalID: id}
pkt, _ := b.Build(probe, garagat.EncodeTimestamp(garagat.TimestampNow()))
reply, ok := garagat.Parse(data, garagat.LinkTypeEthernet, captureMicros)
```

`link.NewSimulated` returns a link that answers probes with a function you provide, so tools built on garagat can be tested without privileges. Two tools from caracat are ported as examples:

```bash
sudo go run ./examples/traceroute -A -e google.com
sudo go run ./examples/yarrp -i targets.txt -r 1000 -o output.yrp
```

## Platforms

| OS | Send and capture | Default routes |
| --- | --- | --- |
| Linux | `AF_PACKET` raw socket, kernel BPF filter, `SO_TIMESTAMPNS` timestamps, `PACKET_STATISTICS` | `/proc/net/route`, `/proc/net/ipv6_route` |
| macOS, FreeBSD | `/dev/bpf` with `BIOCSETF`, `BIOCSHDRCMPLT`, kernel timestamps, `BIOCGSTATS` | routing socket (`golang.org/x/net/route`) |

Ethernet, BSD loopback (`DLT_NULL`) and raw IP links are supported. Linux and macOS do not answer probes injected on the loopback interface (`lo`, `lo0`), so probing `127.0.0.1` through it gets no replies; capturing on it works. This is also true for caracal.

## Differences from caracal

The probe encoding, CSV output and flags are the same. The differences are:

- No libpcap, libtins or liblpm: raw sockets, BPF programs, the pcap writer and the prefix trie are written in Go.
- The IPv4 and IPv6 gateways are resolved separately (caracal uses the IPv4 gateway MAC for both), with active ARP and NDP like caracat. `--gateway-mac-v4` and `--gateway-mac-v6` override them.
- `--source-address-v4` and `--source-address-v6` work (caracal reads the wrong option name and fails).
- The CSV output is flushed every 100 ms while capturing, instead of when the buffer fills.
- SIGINT and SIGTERM stop probing cleanly; `--output-file-pcap` and `--dry-run` are exposed as flags.
- Probe CSV fields may contain surrounding spaces and Windows line endings.
- Outer IPv6 extension headers (hop-by-hop, routing, destination options) and VLAN tags are skipped when parsing replies.

## Performance

On one core (Apple M-series, Linux container), building a probe takes about 55 ns, parsing a reply 75 ns and formatting a CSV line 400 ns. The CLI sends about 350k probes per second with `--rate-limiting-method none`. Run `make bench` for the micro-benchmarks.

## Development

```bash
make test         # unit tests with the race detector
make lint         # go vet and gofmt
make cross        # build for linux, darwin and freebsd without cgo
make integration  # real-network tests in a Linux container (needs Docker)
```

The unit tests need no privileges: the parser is tested against caracal's captures, the builder is tested byte-for-byte against the probes in those captures, the kernel filters run in a BPF virtual machine, and the prober runs end to end against a simulated network. The integration tests (`-tags integration`) send real packets and need root.

## Credits and license

caracal was written by [Kévin Vermeulen](https://github.com/kvermeul), with refactoring and improvements by [Maxime Mouchet](https://github.com/maxmouchet) and [Matthieu Gouel](https://github.com/matthieugouel), at the Dioptra group of Sorbonne Université. caracat is Maxime Mouchet's Rust port. The test captures in `testdata/` come from caracal. garagat is released under the [MIT license](LICENSE), like caracal and caracat.
