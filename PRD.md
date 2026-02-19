# Product Requirements Document: ErlVPN
## A High-Performance VPN Built in Erlang over HTTP/3 (QUIC)

**Version:** 1.0
**Date:** 2026-02-18
**Status:** Draft

---

## 1. Executive Summary

ErlVPN is a modern, high-performance VPN server built in Erlang/OTP using HTTP/3 (QUIC) as its transport layer. It leverages Erlang's battle-tested concurrency model (one lightweight process per client) and QUIC's built-in TLS 1.3 encryption, 0-RTT reconnection, connection migration, and multiplexed streams to deliver a VPN that is fast, fault-tolerant, and resistant to censorship.

### Why Erlang + HTTP/3?

| Property | Benefit |
|----------|---------|
| **Erlang's process model** | One process per client = fault isolation, no shared mutable state, linear horizontal scaling |
| **OTP supervision trees** | Self-healing — crashed sessions restart automatically without affecting other clients |
| **BEAM scheduler** | Preemptive scheduling across all CPU cores with no manual thread management |
| **Per-process GC** | No stop-the-world pauses even with 100K+ concurrent connections |
| **Hot code reload** | Update encryption, routing, or auth logic without disconnecting any client |
| **QUIC/HTTP3 transport** | Built-in TLS 1.3, 0-RTT resumption, connection migration, NAT-friendly UDP |
| **Censorship resistance** | QUIC on port 443 looks like normal web traffic; very hard to block |

### Project Codename: `erlvpn`

---

## 2. Goals & Non-Goals

### Goals

1. **Build a production-capable VPN server** in Erlang that supports 10K+ concurrent clients on a single node
2. **Use QUIC (via quicer) as the primary transport**, with HTTP/3 framing for censorship resistance
3. **Support all core VPN features**: tunneling (TUN), IP assignment, DNS resolution, split tunneling, kill switch coordination, authentication
4. **Achieve competitive throughput**: target ≥1 Gbps per server node with sub-5ms added latency for packet forwarding
5. **Provide a reference CLI client** (initially Linux/macOS) for testing and development
6. **Design for horizontal scaling**: stateless server design allowing load balancing across multiple nodes via Erlang distribution or external orchestration

### Non-Goals (v1)

- Mobile clients (iOS/Android) — deferred to v2
- Windows client — deferred to v2
- GUI client applications — CLI only for v1
- Commercial billing/subscription system
- Multi-hop/relay chains (Tor-style)
- Kernel-space packet processing (e.g., eBPF, XDP) — userspace only for v1

---

## 3. Architecture Overview

### 3.1 High-Level System Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        ErlVPN Server                        │
│                                                             │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────────┐  │
│  │  QUIC    │    │  Session     │    │    TUN Device      │  │
│  │ Listener │───▶│  Supervisor  │───▶│    (tunctl)        │  │
│  │ (quicer) │    │  (1 proc/    │    │                    │  │
│  │          │    │   client)    │    │  ┌──────────────┐  │  │
│  └──────────┘    └──────┬───────┘    │  │ TUN Reader   │  │  │
│                         │            │  │ Process      │  │  │
│                         │            │  └──────┬───────┘  │  │
│                         ▼            │         │          │  │
│                  ┌──────────────┐    └─────────┼──────────┘  │
│                  │  ETS Routing │◀─────────────┘             │
│                  │  Table       │                             │
│                  └──────────────┘                             │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │
│  │ IP Pool  │  │   DNS    │  │  Auth    │  │   Metrics   │  │
│  │ Manager  │  │ Resolver │  │ Manager  │  │  Collector  │  │
│  └──────────┘  └──────────┘  └──────────┘  └─────────────┘  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
         │                                        ▲
         ▼                                        │
   ┌───────────┐                           ┌──────────────┐
   │  Internet │                           │  VPN Client  │
   │           │                           │  (QUIC)      │
   └───────────┘                           └──────────────┘
```

### 3.2 OTP Supervision Tree

```
erlvpn_app
  └── erlvpn_sup (one_for_one)
        ├── erlvpn_quic_listener        (worker: gen_server)
        │     Accepts incoming QUIC connections
        │
        ├── erlvpn_session_sup          (supervisor: simple_one_for_one)
        │     └── erlvpn_session        (gen_statem per client)
        │           Manages: auth → tunnel setup → active forwarding → teardown
        │
        ├── erlvpn_tun_manager          (worker: gen_server)
        │     Creates/manages the shared TUN device
        │     Spawns tun_reader process for inbound packet dispatch
        │
        ├── erlvpn_router               (worker: gen_server + ETS)
        │     Maintains IP → {ClientPid, QUICStream} mapping
        │     ETS ordered_set with read_concurrency for fast lookups
        │
        ├── erlvpn_ip_pool              (worker: gen_server)
        │     Allocates/deallocates tunnel IPs from configured CIDR
        │
        ├── erlvpn_dns                  (worker: gen_server)
        │     Resolves DNS queries from tunnel clients
        │     Prevents DNS leaks by handling all client DNS traffic
        │
        ├── erlvpn_auth                 (worker: gen_server)
        │     Token/certificate-based client authentication
        │
        └── erlvpn_metrics              (worker: gen_server)
              Tracks bandwidth, connections, latency, errors
```

### 3.3 Packet Flow

**Client → Internet (Ingress):**
```
Client App → [QUIC Stream/Datagram] → erlvpn_session process
  → decrypt/validate → tunctl:write(TunFd, Packet) → TUN device
  → kernel IP forwarding → Internet
```

**Internet → Client (Egress):**
```
Internet → kernel routing → TUN device → tun_reader process
  → {tuntap, Pid, Packet} → extract dest IP
  → ets:lookup(routing_table, DestIP) → {ClientPid, Stream}
  → erlvpn_session:send(ClientPid, Packet)
  → quicer:send(Stream, Packet) → Client
```

---

## 4. Technical Stack

| Component | Technology | Notes |
|-----------|-----------|-------|
| **Language** | Erlang/OTP 27+ | BEAM VM with JIT compiler |
| **Build tool** | rebar3 | Standard Erlang build system |
| **QUIC transport** | [quicer](https://github.com/emqx/quic) (v0.2.x) | Wraps Microsoft MsQuic via NIFs |
| **TUN/TAP** | [tunctl](https://github.com/msantos/tunctl) | Linux/macOS/FreeBSD support |
| **Packet parsing** | [pkt](https://github.com/msantos/pkt) | IPv4/IPv6/TCP/UDP header parsing |
| **Crypto** | OTP `crypto` module | ChaCha20-Poly1305, AES-256-GCM, Curve25519, HKDF |
| **Optional crypto** | [enacl](https://github.com/jlouis/enacl) | libsodium bindings for NaCl-style API |
| **Configuration** | OTP application env + TOML | Server config via `sys.config` + TOML files |
| **Logging** | OTP `logger` | Structured logging with configurable levels |
| **Metrics** | Prometheus via `prometheus.erl` | Exposed via HTTP endpoint |
| **Testing** | EUnit + Common Test + PropEr | Unit, integration, and property-based testing |

---

## 5. Core Features (v1)

### 5.1 QUIC Transport Layer

**Requirements:**
- Accept QUIC connections on a configurable port (default: 443)
- ALPN negotiation with protocol identifier `"erlvpn"` (and optionally `"h3"` for HTTP/3 masquerading mode)
- TLS 1.3 with certificate-based server authentication
- Support both QUIC streams (reliable, ordered) and QUIC datagrams (unreliable, unordered — RFC 9221)
- Connection migration support (client IP/port changes handled transparently)
- 0-RTT session resumption for returning clients

**Transport Modes:**

| Mode | Use Case | Framing |
|------|----------|---------|
| **Raw QUIC Streams** | Default mode; reliable packet delivery | Length-prefixed binary frames |
| **QUIC Datagrams** | Low-latency mode for UDP-like traffic (gaming, VoIP) | Raw IP packets in QUIC DATAGRAM frames |
| **HTTP/3 CONNECT** | Censorship-resistance mode; looks like web traffic | MASQUE CONNECT-IP over HTTP/3 |

**Control vs Data Separation:**
- Stream 0 (bidirectional): Control channel — authentication, config push, keepalives, IP assignment
- Stream 2+ (bidirectional): Data channel — tunneled IP packets
- Datagrams: Optional fast-path for latency-sensitive traffic

### 5.2 Client Authentication

**Supported Methods:**
1. **Token-based (primary):** Client presents a pre-shared token during the control handshake. Server validates against a local token store.
2. **Certificate-based (mutual TLS):** Client presents a TLS client certificate during the QUIC handshake. Server validates against a CA or allowlist.
3. **Username/Password:** Client sends credentials over the encrypted control channel. Server validates against a configurable backend (local file, HTTP API callback).

**Authentication Flow:**
```
Client                              Server
  │                                    │
  │──── QUIC Handshake (TLS 1.3) ────▶│  (server cert verified by client)
  │                                    │
  │──── Control: AUTH {method, creds} ─▶│
  │                                    │── validate credentials
  │◀─── Control: AUTH_OK {config} ─────│
  │     (tunnel IP, DNS, routes, MTU)  │
  │                                    │
  │──── Data: IP packets ─────────────▶│
  │◀─── Data: IP packets ─────────────│
```

**Session Tokens:**
- On successful auth, server issues a session token (opaque, signed)
- Client can use session token for 0-RTT reconnection without full re-auth
- Tokens have configurable TTL (default: 24 hours)
- Tokens bound to client public key to prevent theft

### 5.3 Tunnel Management

**TUN Device:**
- Single shared TUN device for all clients (like WireGuard's approach)
- Created at server startup via `tunctl:create([tun, no_pi, {active, true}])`
- Assigned the server-side tunnel IP (e.g., `10.8.0.1/16`)
- Kernel IP forwarding enabled (`sysctl net.ipv4.ip_forward=1`)
- NAT/masquerade rules (iptables/nftables) for outbound traffic

**IP Address Assignment:**
- Configurable CIDR pool (default: `10.8.0.0/16` — supports 65,534 clients)
- IP allocated on successful authentication, returned to pool on disconnect
- Allocation tracked in ETS for O(1) lookup
- Lease-based: IPs reclaimed after session timeout even if client doesn't cleanly disconnect
- Support for both IPv4 and IPv6 tunnel addresses

**MTU Handling:**
- Server advertises tunnel MTU to client during config push
- Default tunnel MTU: 1280 (conservative, works with all QUIC paths)
- Optional PMTUD: Server probes path MTU and adjusts dynamically
- Client must clamp TCP MSS to (MTU - 40) for IPv4 or (MTU - 60) for IPv6

### 5.4 Routing & Packet Forwarding

**Routing Table (ETS):**
```erlang
%% Table: erlvpn_routes (ordered_set, public, read_concurrency)
%% Key: {TunnelIP}  → Value: {ClientPid, QUICStream, Metadata}

%% Insert on client connect
ets:insert(erlvpn_routes, {{10,8,0,5}, Pid, StreamRef, #{connected => erlang:monotonic_time()}}).

%% Lookup for outbound packet routing
case ets:lookup(erlvpn_routes, DestIP) of
    [{_, Pid, Stream, _}] -> erlvpn_session:forward(Pid, Packet);
    [] -> drop  %% no route to client
end.
```

**Split Tunneling:**
- Server pushes a list of routes to the client during config:
  - `allowed_ips`: CIDRs that should go through the tunnel (default: `0.0.0.0/0` = full tunnel)
  - `excluded_ips`: CIDRs that should bypass the tunnel
  - `dns_routes`: Force DNS traffic through tunnel regardless of split tunnel config
- Client is responsible for configuring OS routing table based on pushed routes

**Inter-Client Routing:**
- Optional: Allow clients on the same server to communicate through the tunnel
- Packet with dest IP matching another client's tunnel IP is routed directly (no TUN device round-trip)
- Controlled by server configuration flag: `allow_client_to_client` (default: `false`)

### 5.5 DNS Resolution

**Architecture:**
- Built-in DNS resolver that handles queries from tunnel clients
- Listens on the server's tunnel IP (e.g., `10.8.0.1:53`)
- Forwards queries to configurable upstream DNS servers (default: `1.1.1.1`, `8.8.8.8`)
- Caches responses with TTL-based expiration

**DNS Leak Prevention:**
- Server pushes DNS configuration to client: `{dns_servers, [{10,8,0,1}]}`
- Client configures system DNS to use only the tunnel DNS
- Server can optionally block DNS queries that arrive on the data channel destined for external DNS servers (detect and redirect)

**DNS-over-HTTPS (DoH) Support:**
- Upstream queries from server to public DNS can use DoH
- Prevents ISP-level DNS snooping on the server's upstream path

### 5.6 Session Management (gen_statem)

**Client Session States:**

```
    ┌───────────┐
    │ connecting │ ── QUIC handshake complete ──▶ ┌────────────────┐
    └───────────┘                                 │ authenticating │
                                                  └───────┬────────┘
                                                          │
                                              auth success │ auth fail
                                                          │     │
                                                          ▼     ▼
                                              ┌──────────┐  ┌──────┐
                                              │ active   │  │ stop │
                                              └────┬─────┘  └──────┘
                                                   │
                                        disconnect/timeout/error
                                                   │
                                                   ▼
                                           ┌──────────────┐
                                           │ disconnecting│ → cleanup → stop
                                           └──────────────┘
```

**Per-Session Responsibilities:**
- Authenticate the client
- Request IP allocation from `erlvpn_ip_pool`
- Register route in `erlvpn_router`
- Forward packets between QUIC stream and TUN device
- Handle keepalives (send/receive every 25 seconds)
- Track bandwidth usage per session
- Clean up on disconnect: release IP, remove route, close QUIC streams

**Session Persistence:**
- Session state (token, allocated IP, bandwidth counters) stored in ETS
- On 0-RTT reconnection, server can restore previous session state
- If same client reconnects and old session still exists, old session is terminated gracefully

### 5.7 Kill Switch Coordination

The kill switch is primarily a **client-side** feature, but the server coordinates it:

**Server's Role:**
- Sends keepalive frames every 25 seconds on the control channel
- If client doesn't receive keepalive within timeout (configurable, default: 60s), client activates kill switch
- On reconnection, server sends `KILL_SWITCH_RELEASE` control message

**Client's Role (reference implementation):**
- On VPN connection: install firewall rules allowing only VPN traffic
  - Linux: `iptables -A OUTPUT -o tun0 -j ACCEPT && iptables -A OUTPUT -o lo -j ACCEPT && iptables -A OUTPUT -d <server_ip> -p udp --dport 443 -j ACCEPT && iptables -A OUTPUT -j DROP`
  - macOS: equivalent `pf` rules
- On VPN disconnect/timeout: rules remain active (all non-VPN traffic blocked)
- On intentional VPN disable: remove firewall rules
- Rules are installed as persistent (survive VPN process crash)

### 5.8 Logging & Metrics

**Structured Logging:**
- OTP `logger` with JSON formatter for production
- Log levels: `debug`, `info`, `notice`, `warning`, `error`
- Per-session log metadata: `{client_id, tunnel_ip, session_id}`
- Sensitive data (tokens, keys) never logged

**Metrics (Prometheus):**

| Metric | Type | Description |
|--------|------|-------------|
| `erlvpn_connections_active` | Gauge | Currently connected clients |
| `erlvpn_connections_total` | Counter | Total connections since start |
| `erlvpn_auth_failures_total` | Counter | Failed authentication attempts |
| `erlvpn_bytes_rx_total` | Counter | Total bytes received from clients |
| `erlvpn_bytes_tx_total` | Counter | Total bytes sent to clients |
| `erlvpn_packets_rx_total` | Counter | Total packets received |
| `erlvpn_packets_tx_total` | Counter | Total packets sent |
| `erlvpn_packet_forward_duration` | Histogram | Packet forwarding latency |
| `erlvpn_ip_pool_available` | Gauge | Available IPs in pool |
| `erlvpn_dns_queries_total` | Counter | DNS queries handled |
| `erlvpn_session_duration_seconds` | Histogram | Session durations |
| `erlvpn_quic_0rtt_resumptions_total` | Counter | Successful 0-RTT resumptions |

**Health Endpoint:**
- HTTP endpoint on a separate port (default: 9100) for health checks and metrics scraping
- `GET /health` → `200 OK` with basic status
- `GET /metrics` → Prometheus text format

---

## 6. Control Protocol

Binary protocol over QUIC Stream 0 (control channel).

### 6.1 Frame Format

```
┌──────────┬──────────┬─────────────────────┐
│ Type (1B)│ Len (2B) │ Payload (variable)  │
└──────────┴──────────┴─────────────────────┘
```

- **Type**: 1 byte, identifies the message type
- **Length**: 2 bytes (big-endian), length of payload
- **Payload**: Variable-length, type-specific content (Erlang External Term Format or MessagePack)

### 6.2 Message Types

| Type | Code | Direction | Payload |
|------|------|-----------|---------|
| `AUTH_REQUEST` | `0x01` | C → S | `{method, credentials}` |
| `AUTH_RESPONSE` | `0x02` | S → C | `{status, session_token \| error_reason}` |
| `CONFIG_PUSH` | `0x03` | S → C | `{tunnel_ip, dns, routes, mtu, keepalive_interval}` |
| `KEEPALIVE` | `0x04` | Both | `{timestamp}` |
| `KEEPALIVE_ACK` | `0x05` | Both | `{timestamp}` |
| `DISCONNECT` | `0x06` | Both | `{reason}` |
| `BANDWIDTH_REPORT` | `0x07` | S → C | `{rx_bytes, tx_bytes, rx_packets, tx_packets}` |
| `ROUTE_UPDATE` | `0x08` | S → C | `{add_routes, remove_routes}` |
| `DNS_CONFIG` | `0x09` | S → C | `{dns_servers, search_domains}` |
| `KILL_SWITCH` | `0x0A` | S → C | `{activate \| release}` |
| `SESSION_RESUME` | `0x0B` | C → S | `{session_token}` |
| `ERROR` | `0xFF` | Both | `{error_code, message}` |

### 6.3 Data Channel Frame Format

For QUIC Streams (reliable):
```
┌──────────┬─────────────────────┐
│ Len (2B) │ IP Packet (variable)│
└──────────┴─────────────────────┘
```

For QUIC Datagrams (unreliable):
```
┌─────────────────────┐
│ IP Packet (raw)     │  (no framing needed; one datagram = one IP packet)
└─────────────────────┘
```

---

## 7. Configuration

### 7.1 Server Configuration (`erlvpn.toml`)

```toml
[server]
listen_port = 443
listen_address = "0.0.0.0"
max_clients = 10000
log_level = "info"

[tls]
cert_file = "/etc/erlvpn/server.crt"
key_file = "/etc/erlvpn/server.key"
# Optional: CA for mutual TLS client auth
# client_ca_file = "/etc/erlvpn/ca.crt"

[tunnel]
device_name = "erlvpn0"
ipv4_cidr = "10.8.0.0/16"
ipv6_cidr = "fd00:erlvpn::/64"
mtu = 1280
enable_ipv6 = true

[routing]
# Routes pushed to clients (CIDR list)
# "0.0.0.0/0" = full tunnel, or specify split tunnel CIDRs
allowed_ips = ["0.0.0.0/0", "::/0"]
excluded_ips = []
allow_client_to_client = false
enable_nat = true

[dns]
enabled = true
upstream_servers = ["1.1.1.1", "8.8.8.8"]
upstream_doh = true
cache_size = 10000
# Custom DNS records (for internal domains)
# [dns.records]
# "internal.vpn" = "10.8.0.1"

[auth]
method = "token"  # "token", "certificate", "password"
token_file = "/etc/erlvpn/tokens"
session_token_ttl = "24h"
max_auth_attempts = 5
auth_timeout = "30s"

[keepalive]
interval = 25       # seconds
timeout = 60         # seconds; disconnect if no response
kill_switch_timeout = 60  # seconds; client activates kill switch

[performance]
schedulers = auto    # "auto" = number of CPU cores
quic_max_streams_per_connection = 4
quic_datagram_enabled = true
tun_read_batch_size = 64  # packets per read batch

[metrics]
enabled = true
listen_port = 9100
listen_address = "127.0.0.1"

[logging]
level = "info"
format = "json"       # "json" or "text"
file = "/var/log/erlvpn/erlvpn.log"
max_file_size = "100MB"
max_files = 10
```

### 7.2 Client Configuration (`client.toml`)

```toml
[connection]
server_address = "vpn.example.com"
server_port = 443
transport_mode = "quic_stream"  # "quic_stream", "quic_datagram", "http3"

[auth]
method = "token"
token = "your-auth-token-here"
# Or for certificate auth:
# method = "certificate"
# cert_file = "~/.erlvpn/client.crt"
# key_file = "~/.erlvpn/client.key"

[tunnel]
# Override server-pushed routes (optional)
# allowed_ips = ["10.0.0.0/8"]
# excluded_ips = ["192.168.1.0/24"]

[dns]
# Override server-pushed DNS (optional)
# servers = ["10.8.0.1"]

[kill_switch]
enabled = true
mode = "system"  # "system" (block all) or "app" (per-app)

[advanced]
mtu = 1280
reconnect_attempts = 10
reconnect_backoff_max = "30s"
enable_0rtt = true
```

---

## 8. Security Model

### 8.1 Threat Model

| Threat | Mitigation |
|--------|-----------|
| **Eavesdropping on tunnel traffic** | QUIC mandates TLS 1.3 with forward secrecy; all data encrypted |
| **MITM on connection** | Server certificate pinning; optional mutual TLS |
| **Replay attacks** | QUIC's built-in anti-replay for 0-RTT; session tokens bound to connection |
| **DNS leaks** | Server-side DNS resolver; client-side DNS redirect; block external DNS |
| **IP leaks (WebRTC, etc.)** | Client-side firewall rules (kill switch); server pushes full tunnel routes |
| **Traffic analysis** | QUIC on port 443 blends with web traffic; optional padding |
| **Token theft** | Tokens bound to client TLS certificate/public key; short TTL |
| **DoS on server** | Rate limiting per IP; max connections per account; QUIC's address validation |
| **Privilege escalation** | Server drops privileges after TUN setup; runs as non-root with CAP_NET_ADMIN |
| **Memory corruption (NIF)** | quicer NIFs are battle-tested in EMQX production; tunctl uses ports (not NIFs) |

### 8.2 Cryptographic Choices

- **Transport encryption**: TLS 1.3 via QUIC (mandatory)
- **Cipher suites**: `TLS_CHACHA20_POLY1305_SHA256` (preferred), `TLS_AES_256_GCM_SHA384` (fallback)
- **Key exchange**: X25519 (preferred), P-256 (fallback)
- **Session tokens**: HMAC-SHA256 signed, containing `{client_id, tunnel_ip, expiry, nonce}`
- **Auth tokens**: Argon2id hashed when stored server-side

### 8.3 Privilege Model

```
Startup (root):
  1. Bind to port 443
  2. Create TUN device
  3. Configure routing/NAT rules
  4. Drop to unprivileged user (erlvpn:erlvpn)

Runtime (erlvpn user):
  - CAP_NET_ADMIN (manage TUN device)
  - CAP_NET_BIND_SERVICE (bind port < 1024)
  - No other capabilities
```

---

## 9. Client Reference Implementation

### 9.1 Scope (v1)

A command-line client written in Erlang for Linux and macOS. This serves as both a reference implementation and a usable client.

### 9.2 Commands

```bash
# Connect to VPN server
erlvpn connect --config /path/to/client.toml

# Connect with inline options
erlvpn connect --server vpn.example.com --token "mytoken"

# Disconnect
erlvpn disconnect

# Show connection status
erlvpn status

# Generate a new client token (server-side admin tool)
erlvpn-admin generate-token --name "user1" --expires "30d"

# List connected clients (server-side admin tool)
erlvpn-admin list-clients

# Revoke a token
erlvpn-admin revoke-token --name "user1"
```

### 9.3 Client Architecture

```
erlvpn_client_app
  └── erlvpn_client_sup (one_for_one)
        ├── erlvpn_client_conn       (gen_statem)
        │     QUIC connection management + auth
        │
        ├── erlvpn_client_tun        (gen_server)
        │     TUN device + routing table setup
        │
        ├── erlvpn_client_dns        (gen_server)
        │     System DNS configuration
        │
        ├── erlvpn_client_killswitch (gen_server)
        │     Firewall rule management
        │
        └── erlvpn_client_forwarder  (gen_server)
              Packet forwarding between TUN and QUIC
```

---

## 10. Performance Targets

| Metric | Target | Measurement Method |
|--------|--------|--------------------|
| **Throughput (single client)** | ≥ 500 Mbps | iperf3 through tunnel |
| **Throughput (aggregate, 1K clients)** | ≥ 1 Gbps | iperf3 aggregate |
| **Added latency** | < 5 ms | ping through tunnel vs. direct |
| **Connection setup time** | < 200 ms (1-RTT), < 50 ms (0-RTT) | Time from connect to first data packet |
| **Concurrent connections** | ≥ 10,000 | Sustained connected clients |
| **Memory per client** | < 50 KB | BEAM process + buffers |
| **Reconnection time** | < 100 ms (0-RTT) | Time to resume forwarding after network change |
| **CPU usage** | < 50% at 1 Gbps aggregate | System CPU on 4-core server |

---

## 11. Testing Strategy

### 11.1 Unit Tests (EUnit)

- Packet parsing and serialization
- IP pool allocation/deallocation
- Routing table operations
- Control protocol encoding/decoding
- Authentication logic
- DNS query/response handling
- Configuration parsing

### 11.2 Integration Tests (Common Test)

- Full client-server connection lifecycle
- Authentication flows (success, failure, retry)
- Packet forwarding through tunnel (ICMP, TCP, UDP)
- DNS resolution through tunnel
- Connection migration simulation
- 0-RTT session resumption
- Kill switch activation/deactivation
- Client disconnect and cleanup
- Multiple concurrent clients

### 11.3 Property-Based Tests (PropEr)

- Packet encoding/decoding round-trips
- IP pool: all allocated IPs are unique, freed IPs can be reallocated
- Routing table: insert/delete consistency
- Control protocol: encode(decode(X)) == X

### 11.4 Performance Tests

- Throughput benchmarks: single client, 100 clients, 1000 clients
- Latency benchmarks: packet forwarding time
- Connection storm: 10K clients connecting simultaneously
- Long-running stability: 24-hour continuous test with traffic
- Memory leak detection: monitor BEAM memory over extended operation

---

## 12. Deployment

### 12.1 System Requirements

- **OS**: Linux (primary), macOS (development)
- **Erlang/OTP**: 27+ (required for latest crypto and JIT)
- **Kernel**: Linux 4.19+ (for modern TUN support)
- **Capabilities**: `CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`
- **RAM**: 512 MB minimum, 2 GB recommended for 10K clients
- **CPU**: 2 cores minimum, 4+ recommended

### 12.2 Installation

```bash
# Build from source
git clone <repo>
cd erlvpn
rebar3 release

# Generate TLS certificates
erlvpn-admin generate-certs --domain vpn.example.com

# Generate initial auth tokens
erlvpn-admin generate-token --name "admin" --expires "365d"

# Start server
_build/default/rel/erlvpn/bin/erlvpn foreground
# Or as a systemd service
sudo systemctl start erlvpn
```

### 12.3 Systemd Service

```ini
[Unit]
Description=ErlVPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=erlvpn
Group=erlvpn
ExecStart=/opt/erlvpn/bin/erlvpn foreground
ExecStop=/opt/erlvpn/bin/erlvpn stop
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

---

## 13. Project Structure

```
erlvpn/
├── rebar.config                 # Dependencies and build config
├── rebar.lock
├── erlvpn.toml                  # Default server configuration
├── client.toml                  # Default client configuration
├── config/
│   ├── sys.config               # OTP application config
│   └── vm.args                  # BEAM VM arguments
├── apps/
│   ├── erlvpn_server/           # Server application
│   │   ├── src/
│   │   │   ├── erlvpn_server_app.erl
│   │   │   ├── erlvpn_server_sup.erl
│   │   │   ├── erlvpn_quic_listener.erl
│   │   │   ├── erlvpn_session.erl          # gen_statem per client
│   │   │   ├── erlvpn_session_sup.erl
│   │   │   ├── erlvpn_tun_manager.erl
│   │   │   ├── erlvpn_router.erl
│   │   │   ├── erlvpn_ip_pool.erl
│   │   │   ├── erlvpn_dns.erl
│   │   │   ├── erlvpn_auth.erl
│   │   │   ├── erlvpn_metrics.erl
│   │   │   ├── erlvpn_config.erl
│   │   │   └── erlvpn_protocol.erl         # Control protocol encode/decode
│   │   └── include/
│   │       └── erlvpn.hrl                  # Shared records and macros
│   │
│   ├── erlvpn_client/           # Client application
│   │   ├── src/
│   │   │   ├── erlvpn_client_app.erl
│   │   │   ├── erlvpn_client_sup.erl
│   │   │   ├── erlvpn_client_conn.erl      # gen_statem
│   │   │   ├── erlvpn_client_tun.erl
│   │   │   ├── erlvpn_client_dns.erl
│   │   │   ├── erlvpn_client_killswitch.erl
│   │   │   └── erlvpn_client_forwarder.erl
│   │   └── include/
│   │
│   └── erlvpn_common/           # Shared code
│       └── src/
│           ├── erlvpn_protocol.erl         # Wire protocol
│           ├── erlvpn_packet.erl           # IP packet utilities
│           └── erlvpn_crypto.erl           # Shared crypto helpers
│
├── test/
│   ├── erlvpn_session_SUITE.erl
│   ├── erlvpn_router_SUITE.erl
│   ├── erlvpn_ip_pool_SUITE.erl
│   ├── erlvpn_protocol_SUITE.erl
│   ├── erlvpn_dns_SUITE.erl
│   ├── erlvpn_integration_SUITE.erl
│   └── prop_erlvpn_protocol.erl
│
├── scripts/
│   ├── setup-tun.sh             # TUN device setup helper
│   ├── setup-nat.sh             # NAT/iptables setup helper
│   └── generate-certs.sh        # TLS certificate generation
│
└── docs/
    ├── protocol.md              # Wire protocol specification
    └── deployment.md            # Production deployment guide
```

---

## 14. Implementation Phases

### Phase 1: Foundation (Week 1-2)
- [ ] Project scaffolding with rebar3 (umbrella app)
- [ ] QUIC listener with quicer (accept connections, echo server)
- [ ] TUN device creation and basic read/write with tunctl
- [ ] Control protocol encoding/decoding
- [ ] Basic IP pool (allocate/free)
- [ ] Unit tests for protocol, IP pool

### Phase 2: Core VPN (Week 3-4)
- [ ] Client session gen_statem (full state machine)
- [ ] Token-based authentication
- [ ] ETS routing table
- [ ] Bidirectional packet forwarding (client ↔ TUN ↔ internet)
- [ ] End-to-end tunnel test: client connects, gets IP, pings through tunnel
- [ ] Basic client CLI (`erlvpn connect`, `erlvpn status`)

### Phase 3: DNS & Routing (Week 5)
- [ ] DNS resolver (forward queries to upstream)
- [ ] DNS leak prevention (client-side DNS config)
- [ ] Split tunneling (route push to client)
- [ ] NAT/masquerade setup automation
- [ ] Integration tests for DNS and routing

### Phase 4: Resilience & Security (Week 6)
- [ ] 0-RTT session resumption
- [ ] Connection migration handling
- [ ] Kill switch (client-side firewall rules)
- [ ] Keepalive and timeout handling
- [ ] Rate limiting and DoS protection
- [ ] Privilege dropping after startup

### Phase 5: Observability & Polish (Week 7)
- [ ] Prometheus metrics
- [ ] Structured logging
- [ ] Health check endpoint
- [ ] Configuration file parsing (TOML)
- [ ] Admin CLI tools (generate-token, list-clients, revoke-token)

### Phase 6: Performance & Hardening (Week 8)
- [ ] QUIC datagram mode for low-latency traffic
- [ ] Throughput benchmarks and optimization
- [ ] Property-based tests
- [ ] Long-running stability tests
- [ ] Documentation

---

## 15. Dependencies

```erlang
%% rebar.config
{deps, [
    {quicer, "0.2.15"},          %% QUIC transport (MsQuic NIF)
    {tunctl, "0.2.0"},           %% TUN/TAP device management
    {pkt, "0.5.0"},              %% IP packet parsing
    {toml, "0.7.0"},             %% TOML config parsing
    {prometheus, "4.11.0"},      %% Prometheus metrics
    {prometheus_httpd, "2.1.0"}, %% Metrics HTTP endpoint
    {jsone, "1.8.0"}             %% JSON encoding for structured logs
]}.
```

---

## 16. Risks & Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| quicer API breaks between versions | High | Medium | Pin version, vendor if needed, maintain adapter layer |
| QUIC datagram support incomplete in quicer | Medium | Low | Fall back to QUIC streams; datagrams are optional |
| tunctl macOS support limitations | Medium | Medium | Test early on macOS; fall back to raw utun fd if needed |
| Throughput bottleneck in userspace | High | Medium | Profile early; batch packet processing; consider io_uring for Linux |
| QUIC blocked by network middleboxes | Medium | Medium | Implement TCP fallback (WebSocket/HTTP2 CONNECT) in v2 |
| OpenSSL version missing ChaCha20/X25519 | Low | Low | Document minimum OpenSSL 1.1.1; detect at startup |

---

## 17. Success Criteria

The project is considered successful when:

1. A client on Linux/macOS can connect to the server, authenticate, and receive a tunnel IP
2. All IP traffic from the client is routed through the VPN tunnel
3. DNS queries are resolved through the VPN's DNS resolver (no leaks)
4. The client can seamlessly reconnect after a network change (WiFi → cellular simulation)
5. The kill switch blocks all traffic when VPN connection drops
6. The server handles 1,000 concurrent clients with ≥500 Mbps aggregate throughput
7. All unit, integration, and property-based tests pass
8. The server runs stable for 24 hours under continuous load without memory leaks

---

*This is a living document. It will be updated as implementation progresses and design decisions are refined.*
