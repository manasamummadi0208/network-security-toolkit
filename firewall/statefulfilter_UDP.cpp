#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <ctime>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define DIVERT_PORT 8002
#define BUFFER_SIZE 65536
#define SERVER_PORT 12345
#define TIMEOUT_SECONDS 3

int main() {
    int divert_sock;
    sockaddr_in sin{};
    char packet[BUFFER_SIZE];
    ssize_t packet_len;
    socklen_t sin_len = sizeof(sin);
    time_t last_request_time = 0;

    divert_sock = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (divert_sock == -1) {
        perror("socket");
        return 1;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(DIVERT_PORT);
    sin.sin_addr.s_addr = INADDR_ANY;

    if (bind(divert_sock, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == -1) {
        perror("bind");
        close(divert_sock);
        return 1;
    }

    std::cout << "statefulfilter_UDP started. Filtering on port " << SERVER_PORT << "..." << std::endl;

    while (true) {
        packet_len = recvfrom(divert_sock, packet, BUFFER_SIZE, 0,
                              reinterpret_cast<sockaddr*>(&sin), &sin_len);
        if (packet_len == -1) {
            continue;
        }

        ip* ip_hdr = reinterpret_cast<ip*>(packet);

        if (ip_hdr->ip_p == IPPROTO_UDP) {
            udphdr* udp_hdr = reinterpret_cast<udphdr*>(packet + (ip_hdr->ip_hl * 4));
            int src = ntohs(udp_hdr->uh_sport);
            int dst = ntohs(udp_hdr->uh_dport);

            if (dst == SERVER_PORT) {
                // Outgoing Request
                last_request_time = time(nullptr);
                std::cout << "[OUTGOING] Request sent. Timer reset." << std::endl;

                sendto(divert_sock, packet, packet_len, 0,
                       reinterpret_cast<sockaddr*>(&sin), sin_len);

            } else if (src == SERVER_PORT) {
                // Incoming Response
                double elapsed = difftime(time(nullptr), last_request_time);

                if (elapsed <= TIMEOUT_SECONDS) {
                    std::cout << "[ALLOWED] Response received (Elapsed: "
                              << elapsed << "s)" << std::endl;

                    sendto(divert_sock, packet, packet_len, 0,
                           reinterpret_cast<sockaddr*>(&sin), sin_len);
                } else {
                    std::cout << "[BLOCKED] Response too late (Elapsed: "
                              << elapsed << "s > 3s)" << std::endl;
                }

            } else {
                sendto(divert_sock, packet, packet_len, 0,
                       reinterpret_cast<sockaddr*>(&sin), sin_len);
            }

        } else {
            sendto(divert_sock, packet, packet_len, 0,
                   reinterpret_cast<sockaddr*>(&sin), sin_len);
        }
    }

    close(divert_sock);
    return 0;
}