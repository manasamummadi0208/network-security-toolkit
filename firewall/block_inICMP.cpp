#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define DIVERT_PORT 8001
#define BUFFER_SIZE 65536

int main() {
    int divert_sock;
    sockaddr_in sin{};
    char packet[BUFFER_SIZE];
    ssize_t packet_len;
    socklen_t sin_len = sizeof(sin);

    // Create divert socket
    divert_sock = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (divert_sock == -1) {
        perror("socket");
        return 1;
    }

    // Bind to divert port
    sin.sin_family = AF_INET;
    sin.sin_port = htons(DIVERT_PORT);
    sin.sin_addr.s_addr = INADDR_ANY;

    if (bind(divert_sock, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == -1) {
        perror("bind");
        close(divert_sock);
        return 1;
    }

    std::cout << "block_inICMP started. Blocking incoming ICMP except echo replies..." << std::endl;

    while (true) {
        // Receive packet from divert socket
        packet_len = recvfrom(divert_sock, packet, BUFFER_SIZE, 0,
                              reinterpret_cast<sockaddr*>(&sin), &sin_len);

        if (packet_len == -1) {
            perror("recvfrom");
            continue;
        }

        // Parse IP header
        ip* ip_hdr = reinterpret_cast<ip*>(packet);

        // Check if it's an ICMP packet
        if (ip_hdr->ip_p == 1) {
            // Calculate IP header length
            int ip_hdr_len = ip_hdr->ip_hl * 4;

            // Get ICMP header
            icmp* icmp_hdr = reinterpret_cast<icmp*>(packet + ip_hdr_len);

            if (icmp_hdr->icmp_type == ICMP_ECHOREPLY) {
                // Allow ICMP echo replies
                std::cout << "Allowed ICMP Echo Reply from "
                          << inet_ntoa(ip_hdr->ip_src)
                          << " to "
                          << inet_ntoa(ip_hdr->ip_dst)
                          << std::endl;

                // Reinject the packet
                if (sendto(divert_sock, packet, packet_len, 0,
                           reinterpret_cast<sockaddr*>(&sin), sin_len) == -1) {
                    perror("sendto");
                }
            } else {
                // Block all other incoming ICMP packets
                std::cout << "Blocked incoming ICMP type "
                          << static_cast<int>(icmp_hdr->icmp_type)
                          << " from "
                          << inet_ntoa(ip_hdr->ip_src)
                          << " to "
                          << inet_ntoa(ip_hdr->ip_dst)
                          << std::endl;
            }
        } else {
            // Reinject all non-ICMP packets
            if (sendto(divert_sock, packet, packet_len, 0,
                       reinterpret_cast<sockaddr*>(&sin), sin_len) == -1) {
                perror("sendto");
            }
        }
    }

    close(divert_sock);
    return 0;
}