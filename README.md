# Network Security Toolkit in C

A collection of low-level network security tools implemented in C using **FreeBSD divert sockets** and **OpenSSL**, covering stateful packet filtering, transparent IP-level encryption, keyed authentication, and PKI infrastructure setup.

Built as part of ISA 656 – Network Security coursework at George Mason University.

---

## Projects Overview

| Component | Language | Key Concepts |
|---|---|---|
| Stateful Packet Firewall | C | Divert sockets, ICMP/UDP filtering, stateful inspection |
| Transparent IP Encryption & Auth | C, OpenSSL | RC4, MD5-HMAC, IP header manipulation, checksum recalculation |
| PKI Lab | OpenSSL, Apache | CA creation, CSR signing, HTTPS deployment, MITM simulation |

---

## Component 1 — Stateful Packet Firewall

Three user-space firewall programs that intercept and filter packets via FreeBSD's `ipfw` divert socket mechanism.

### `block_allICMP.c`
Blocks **all incoming ICMP packets**, preventing any external host from pinging the FreeBSD VM.

**How it works:**
- Creates a raw divert socket bound to port 8000
- Inspects the IP protocol field of every diverted packet
- Drops packets where `ip_p == IPPROTO_ICMP` (protocol 1); reinjects all others

**Build & run:**
```bash
clang -o block_allICMP block_allICMP.c
sudo ipfw add 100 divert 8000 ip from any to any
sudo ./block_allICMP
```

**Result:** External pings time out with 100% packet loss.

---

### `block_inICMP.c`
Blocks **incoming ICMP echo requests** (type 8) but allows **incoming ICMP echo replies** (type 0), enabling the VM to ping out while remaining invisible to external ping scans.

**How it works:**
- Diverts only incoming traffic (`ip from any to me`)
- Inspects the ICMP type byte in the ICMP header
- Allows type 0 (echo reply); drops everything else

**Build & run:**
```bash
clang -o block_inICMP block_inICMP.c
sudo ipfw flush
sudo ipfw add 60000 allow ip from any to any
sudo ipfw add 100 divert 8001 ip from any to me in
sudo ./block_inICMP
```

**Result:** Incoming pings are blocked; outgoing pings to 8.8.8.8 succeed.

---

### `statefulfilter_UDP.c`
Implements a **stateful UDP filter** with a 3-second timeout window. Only UDP responses that arrive within 3 seconds of the most recent outgoing request are allowed through.

**How it works:**
- Tracks the timestamp of the last outgoing UDP request (`last_request_time`)
- On each incoming UDP response, computes `difftime(now, last_request_time)`
- Allows the packet if elapsed ≤ 3s; drops it otherwise

**Build & run (two VMs required):**
```bash
# VM1 (server)
clang UDPDelayedEcho.c -o UDPDelayedEcho
./UDPDelayedEcho 12345 1 5        # fast delay = 1s, slow delay = 5s

# VM2 (client + firewall)
clang statefulfilter_UDP.c -o statefulfilter_UDP
sudo ipfw flush && sudo ipfw add 60000 allow ip from any to any
sudo ipfw add 100 divert 8002 udp from any to any
sudo ./statefulfilter_UDP

# In a second terminal on VM2
./UDPReqs <VM1_IP> 12345 6 2
```

**Result:** Responses delayed by 1s are ALLOWED; responses delayed by 5s are BLOCKED.

---

## Component 2 — Transparent IP-Level Encryption & Authentication

### `ip_cryptAuthAll.c`

A user-space program that transparently **encrypts outgoing packets** and **authenticates + decrypts incoming packets** for all traffic between two hosts, without modifying the application layer.

**Cryptographic operations:**
- **Outgoing:** RC4-encrypts the IP payload → appends 16-byte `MD5(ciphertext || key)` → adjusts IP total length and recalculates checksum
- **Incoming:** Splits payload into ciphertext `Y` and MAC `Z` → verifies `MD5(Y || key) == Z` → RC4-decrypts `Y` → restores packet to original form

**IP header manipulation:**
- Manually adjusts `ip_len` after payload modification
- Zeroes and recalculates `ip_sum` using a custom `ip_checksum()` function over the IP header words

**Build:**
```bash
cc -Wall -O2 -o ip_cryptAuthAll ip_cryptAuthAll.c -lcrypto
```

**Firewall rules (both VMs):**
```bash
# VM1
sudo ipfw add 100 divert 5000 ip from <VM1_IP> to <VM2_IP>
sudo ipfw add 110 divert 5000 ip from <VM2_IP> to <VM1_IP>

# VM2 (mirror)
sudo ipfw add 100 divert 5000 ip from <VM2_IP> to <VM1_IP>
sudo ipfw add 110 divert 5000 ip from <VM1_IP> to <VM2_IP>
```

**Run:**
```bash
# VM1
sudo ./ip_cryptAuthAll 5000 <VM2_IP> secretKey

# VM2
sudo ./ip_cryptAuthAll 5000 <VM1_IP> secretKey
```

**Experiment A — matching keys:** Ping succeeds with 0% packet loss. Logs show encryption on outgoing and MD5-verified decryption on incoming.

**Experiment B — mismatched keys:** MD5 authentication fails on the receiver side. All packets are dropped (100% packet loss).

**Security analysis:**
- **MITM resistance:** An attacker without the shared key cannot forge valid MD5 tags, so tampered packets are dropped. However, if the key is compromised, an attacker can re-encrypt modified payloads and pass authentication — the scheme has no key exchange mechanism.
- **Replay attack vulnerability:** The scheme has no sequence numbers, timestamps, or nonces. A captured packet remains valid indefinitely and can be replayed to trigger repeated processing at the receiver.

---

## Component 3 — PKI Lab (OpenSSL + Apache)

Demonstrates the full PKI certificate lifecycle and a simulated MITM attack using DNS cache poisoning.

### CA creation
```bash
sudo openssl genrsa -out isa656_ca.key 2048
sudo openssl req -new -x509 -key isa656_ca.key -sha256 -days 3650 -out isa656_ca.crt
```

### Server CSR and certificate signing
```bash
sudo openssl genrsa -out isa656_server.key 2048
sudo openssl req -new -key isa656_server.key -out isa656_server.csr -config isa656server.cnf
sudo openssl x509 -req -in isa656_server.csr -CA isa656_ca.crt -CAkey isa656_ca.key \
  -CAcreateserial -out isa656_server.crt -days 365 -sha256
```

The CNF file sets Subject Alternative Names for `www.isa656Spring2026.com`, `www.isa656.com`, and `www.isa656_Spring2026.com`.

### HTTPS deployment
- Apache VirtualHost configured on port 443 with `SSLEngine on`
- CA certificate imported into Firefox to resolve the untrusted CA warning

### MITM simulation (DNS cache poisoning)
- A fake `www.amazon.com` page hosted locally in Apache
- `/etc/hosts` entry maps `www.amazon.com → 127.0.0.1`
- Firefox loads the attacker-controlled page while showing the real domain in the URL bar
- Browser shows a certificate warning because the server cert (signed by `ISA656_CA`) does not match Amazon's real certificate — demonstrating how PKI protects against this attack class

---

## Environment

- FreeBSD 13 (ARM) VM via VirtualBox
- Ubuntu 20.04 SEED Lab VM (for PKI lab)
- OpenSSL (`-lcrypto` for MD5)
- Apache 2 with SSL module
- `ipfw` for packet diversion rules

---

## Skills Demonstrated

- Raw socket programming in C (`SOCK_RAW`, `IPPROTO_DIVERT`)
- Manual IP header parsing and checksum recalculation
- Stream cipher implementation (RC4 from scratch)
- Keyed message authentication (MD5-HMAC pattern)
- Stateful packet inspection with time-based rules
- PKI certificate lifecycle (CA → CSR → signed cert → HTTPS)
- Attack simulation: reflection attack, DNS cache poisoning, MITM, replay attack analysis
