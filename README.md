# Network Security Toolkit in C++

A collection of low-level network security tools implemented in **C++** using **FreeBSD divert sockets** and **OpenSSL**, covering stateful packet filtering, transparent IP-level encryption, keyed authentication, and PKI infrastructure setup.

Built as part of ISA 656 - Network Security coursework at George Mason University.

This project demonstrates practical understanding of OS-level networking, security mechanisms, and low-level system design.

---

## Key Highlights
- Built low-level packet filtering using FreeBSD divert sockets
- Designed stateful firewall with protocol-level filtering and timeout-based logic
- Implemented IP-layer encryption with integrity verification and checksum handling

---

## Projects Overview

| Component | Language | Key Concepts |
|---|---|---|
| Stateful Packet Firewall | C++ | Divert sockets, ICMP/UDP filtering, stateful inspection |
| Transparent IP Encryption & Auth | C++, OpenSSL | RC4, MD5-based message authentication, IP header manipulation, checksum recalculation |
| PKI Lab | OpenSSL, Apache | CA creation, CSR signing, HTTPS deployment, MITM simulation |

---

## Component 1 - Stateful Packet Firewall

Three user-space firewall programs that intercept and filter packets via FreeBSD's `ipfw` divert socket mechanism.

---

### firewall/block_allICMP.cpp

Blocks **all incoming ICMP packets**, preventing any external host from pinging the FreeBSD VM.

#### How it works:
- Creates a raw divert socket bound to port 8000
- Inspects the IP protocol field of every diverted packet
- Drops packets where `ip_p == IPPROTO_ICMP`
- Reinjects all other packets

#### Build & run:
```bash
g++ -o block_allICMP firewall/block_allICMP.cpp
sudo ipfw add 100 divert 8000 ip from any to any
sudo ./block_allICMP
```

#### Result:
External pings time out with 100% packet loss.

---

### firewall/block_inICMP.cpp

Blocks **incoming ICMP echo requests** while allowing **incoming ICMP echo replies**, enabling the VM to ping out while remaining invisible to external ping scans.

#### How it works:
- Diverts only incoming traffic
- Inspects the ICMP type field
- Allows echo replies
- Drops all other ICMP packets

#### Build & run:
```bash
g++ -o block_inICMP firewall/block_inICMP.cpp
sudo ipfw flush
sudo ipfw add 60000 allow ip from any to any
sudo ipfw add 100 divert 8001 ip from any to me in
sudo ./block_inICMP
```

#### Result:
Incoming pings are blocked while outgoing pings succeed.

---

### firewall/statefulfilter_UDP.cpp

Implements a **stateful UDP filter** with a 3-second timeout.

#### How it works:
- Tracks the last outgoing UDP request time
- Allows responses within 3 seconds
- Blocks delayed responses

#### Build & run:
```bash
# VM1 (server)
g++ UDPDelayedEcho.cpp -o UDPDelayedEcho
./UDPDelayedEcho 12345 1 5

# VM2 (client + firewall)
g++ -o statefulfilter_UDP firewall/statefulfilter_UDP.cpp
sudo ipfw flush && sudo ipfw add 60000 allow ip from any to any
sudo ipfw add 100 divert 8002 udp from any to any
sudo ./statefulfilter_UDP

# In another terminal
./UDPReqs <VM1_IP> 12345 6 2
```

#### Result:
Fast responses are allowed, while delayed responses are blocked.

---

## Component 2 - Transparent IP-Level Encryption & Authentication

### ip-crypt-auth/ip_cryptAuthAll.cpp

Implements **transparent IP-layer encryption and authentication** between distributed hosts.

#### Cryptographic operations:
- Outgoing: RC4 encrypts payload and appends `MD5(ciphertext || key)`
- Incoming: verifies MD5 and decrypts payload

#### IP header handling:
- Updates packet length (`ip_len`)
- Recalculates checksum

#### Build:
```bash
g++ -Wall -O2 -o ip_cryptAuthAll ip-crypt-auth/ip_cryptAuthAll.cpp -lcrypto
```

#### Firewall rules:
```bash
sudo ipfw add 100 divert 5000 ip from <VM1_IP> to <VM2_IP>
sudo ipfw add 110 divert 5000 ip from <VM2_IP> to <VM1_IP>
```

#### Run:
```bash
sudo ./ip_cryptAuthAll 5000 <REMOTE_IP> secretKey
```

#### Results:
- Matching keys → communication succeeds  
- Mismatched keys → packets are dropped  

---

### Security Analysis

- MITM resistance: attacker cannot forge valid authentication without the shared key  
- Replay vulnerability: no timestamps or sequence numbers  
- Key limitation: no secure key exchange mechanism  

---

## Component 3 — PKI Lab (OpenSSL + Apache)

Demonstrates certificate lifecycle and MITM simulation.

### CA Creation
```bash
openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt
```

### Server Certificate
```bash
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -out server.crt
```

### HTTPS Deployment
- Apache configured with SSL
- Certificate installed in browser

### MITM Simulation
- Fake website hosted locally
- DNS spoofing using `/etc/hosts`
- Browser shows certificate mismatch warning

---

## Environment

- FreeBSD VM  
- OpenSSL  
- Apache  
- `ipfw` firewall  

---

## Skills Demonstrated

- Raw socket programming in C++ on FreeBSD (`SOCK_RAW`, `IPPROTO_DIVERT`)
- Low-level packet inspection and filtering  
- IP header parsing and checksum calculation  
- Transparent IP-layer encryption and authentication  
- RC4 encryption implementation  
- MD5-based message authentication  
- Stateful packet filtering  
- PKI lifecycle implementation  
- Security attack simulation (MITM, replay, DNS spoofing)