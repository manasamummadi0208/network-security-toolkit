#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
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
    struct sockaddr_in sin;
    char packet[BUFFER_SIZE];
    ssize_t packet_len;
    socklen_t sin_len = sizeof(sin);
    time_t last_request_time = 0; 

    divert_sock = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (divert_sock == -1) { perror("socket"); exit(1); }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(DIVERT_PORT);
    sin.sin_addr.s_addr = INADDR_ANY;

    if (bind(divert_sock, (struct sockaddr *)&sin, sizeof(sin)) == -1) { perror("bind"); exit(1); }

    printf("statefulfilter_UDP started. Filtering on port %d...\n", SERVER_PORT);

    while (1) {
        packet_len = recvfrom(divert_sock, packet, BUFFER_SIZE, 0, (struct sockaddr *)&sin, &sin_len);
        if (packet_len == -1) continue;

        struct ip *ip_hdr = (struct ip *)packet;
        if (ip_hdr->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_hdr = (struct udphdr *)(packet + (ip_hdr->ip_hl * 4));
            int src = ntohs(udp_hdr->uh_sport);
            int dst = ntohs(udp_hdr->uh_dport);

            if (dst == SERVER_PORT) { // Outgoing Request
                last_request_time = time(NULL);
                printf("[OUTGOING] Request sent. Timer reset.\n");
                sendto(divert_sock, packet, packet_len, 0, (struct sockaddr *)&sin, sin_len);
            } else if (src == SERVER_PORT) { // Incoming Response
                double elapsed = difftime(time(NULL), last_request_time);
                if (elapsed <= TIMEOUT_SECONDS) {
                    printf("[ALLOWED] Response received (Elapsed: %.0fs)\n", elapsed);
                    sendto(divert_sock, packet, packet_len, 0, (struct sockaddr *)&sin, sin_len);
                } else {
                    printf("[BLOCKED] Response too late (Elapsed: %.0fs > 3s)\n", elapsed);
                }
            } else { sendto(divert_sock, packet, packet_len, 0, (struct sockaddr *)&sin, sin_len); }
        } else { sendto(divert_sock, packet, packet_len, 0, (struct sockaddr *)&sin, sin_len); }
    }
}