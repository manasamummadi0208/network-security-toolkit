#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/md5.h>

constexpr int BUFSIZE = 65535;
constexpr int MAXKEY  = 64;

struct RC4_CTX {
    unsigned char S[256];
    unsigned int i, j;
};

static void rc4_init(RC4_CTX* c, const unsigned char* k, int klen) {
    for (int i = 0; i < 256; ++i) {
        c->S[i] = static_cast<unsigned char>(i);
    }

    c->i = 0;
    c->j = 0;

    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + c->S[i] + k[i % klen]) & 0xff;
        unsigned char t = c->S[i];
        c->S[i] = c->S[j];
        c->S[j] = t;
    }
}

static void rc4_crypt(RC4_CTX* c, unsigned char* d, int len) {
    for (int k = 0; k < len; ++k) {
        c->i = (c->i + 1) & 0xff;
        c->j = (c->j + c->S[c->i]) & 0xff;

        unsigned char t = c->S[c->i];
        c->S[c->i] = c->S[c->j];
        c->S[c->j] = t;

        unsigned char rnd = c->S[(c->S[c->i] + c->S[c->j]) & 0xff];
        d[k] ^= rnd;
    }
}

static unsigned short ip_checksum(unsigned short* buf, int nwords) {
    unsigned long sum = 0;

    while (nwords--) {
        sum += *buf++;
        if (sum & 0xffff0000) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }

    return static_cast<unsigned short>(~sum);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <divert_port> <remote_ip> <key>\n";
        return 1;
    }

    const int PORT = std::atoi(argv[1]);
    const std::string remoteHost = argv[2];

    std::string keyStr = argv[3];
    if (static_cast<int>(keyStr.size()) > MAXKEY) {
        keyStr = keyStr.substr(0, MAXKEY);
    }

    const int KLEN = static_cast<int>(keyStr.size());
    std::vector<unsigned char> KEY(keyStr.begin(), keyStr.end());

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(PORT);

    if (bind(s, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) < 0) {
        perror("bind");
        close(s);
        return 1;
    }

    std::cout << "[+] Listening on divert port " << PORT
              << " <-> " << remoteHost << '\n';

    unsigned char buf[BUFSIZE];

    while (true) {
        sockaddr_in rsin{};
        socklen_t rlen = sizeof(rsin);

        ssize_t n = recvfrom(s, buf, sizeof(buf), 0,
                             reinterpret_cast<sockaddr*>(&rsin), &rlen);

        if (n <= 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom");
            break;
        }

        ip* ip_hdr = reinterpret_cast<ip*>(buf);
        int ip_hl = ip_hdr->ip_hl << 2;
        int paylen = ntohs(ip_hdr->ip_len) - ip_hl;
        unsigned char* payload = buf + ip_hl;

        char SRC[INET_ADDRSTRLEN];
        char DST[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &ip_hdr->ip_src, SRC, sizeof(SRC));
        inet_ntop(AF_INET, &ip_hdr->ip_dst, DST, sizeof(DST));

        std::cout << "\nPacket received: " << n << " bytes\n";

        // OUTGOING
        if (remoteHost == DST) {
            std::cout << "Outgoing encrypted packet to " << remoteHost << '\n';

            RC4_CTX c;
            rc4_init(&c, KEY.data(), KLEN);
            rc4_crypt(&c, payload, paylen);

            std::vector<unsigned char> mdin(paylen + KLEN);
            std::memcpy(mdin.data(), payload, paylen);
            std::memcpy(mdin.data() + paylen, KEY.data(), KLEN);

            unsigned char md[MD5_DIGEST_LENGTH];
            MD5(mdin.data(), paylen + KLEN, md);

            std::memcpy(payload + paylen, md, MD5_DIGEST_LENGTH);
            paylen += MD5_DIGEST_LENGTH;

            ip_hdr->ip_len = htons(ip_hl + paylen);
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = ip_checksum(reinterpret_cast<unsigned short*>(ip_hdr), ip_hl >> 1);

            sendto(s, buf, ip_hl + paylen, 0,
                   reinterpret_cast<sockaddr*>(&rsin), sizeof(rsin));

            std::cout << "Outgoing packet sent with encryption + MD5\n";
            continue;
        }

        // INCOMING
        if (remoteHost == SRC) {
            std::cout << "Incoming packet from " << remoteHost << '\n';

            if (paylen < MD5_DIGEST_LENGTH) {
                std::cerr << "Payload < 16 bytes, dropping packet\n";
                continue;
            }

            int ylen = paylen - MD5_DIGEST_LENGTH;
            unsigned char* Y = payload;
            unsigned char* Z = payload + ylen;

            std::vector<unsigned char> mdin(ylen + KLEN);
            std::memcpy(mdin.data(), Y, ylen);
            std::memcpy(mdin.data() + ylen, KEY.data(), KLEN);

            unsigned char md[MD5_DIGEST_LENGTH];
            MD5(mdin.data(), ylen + KLEN, md);

            if (std::memcmp(md, Z, MD5_DIGEST_LENGTH) != 0) {
                std::cerr << "MD5 authentication failed. Dropping packet.\n";
                continue;
            }

            std::cout << "MD5 check passed. Decrypting...\n";

            RC4_CTX c;
            rc4_init(&c, KEY.data(), KLEN);
            rc4_crypt(&c, Y, ylen);

            ip_hdr->ip_len = htons(ip_hl + ylen);
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = ip_checksum(reinterpret_cast<unsigned short*>(ip_hdr), ip_hl >> 1);

            sendto(s, buf, ip_hl + ylen, 0,
                   reinterpret_cast<sockaddr*>(&rsin), sizeof(rsin));

            std::cout << "Decrypted and forwarded packet\n";
            continue;
        }

        // OTHERS
        sendto(s, buf, n, 0, reinterpret_cast<sockaddr*>(&rsin), sizeof(rsin));
        std::cout << "Forwarded unrelated packet\n";
    }

    close(s);
    return 0;
}