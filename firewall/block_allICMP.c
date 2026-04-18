#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define DIVERT_PORT 8000
#define BUFFER_SIZE 65536

int main() {
    int divert_sock;
    struct sockaddr_in sin;
    char packet[BUFFER_SIZE];
    ssize_t packet_len;
    socklen_t sin_len = sizeof(sin);
    
    // Create divert socket
    divert_sock = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (divert_sock == -1) {
        perror("socket");
        exit(1);
    }
    
    // Bind to divert port
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(DIVERT_PORT);
    sin.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(divert_sock, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        perror("bind");
        close(divert_sock);
        exit(1);
    }
    
    printf("block_allICMP started. Blocking all incoming ICMP packets...\n");
    
    while (1) {
        // Receive packet from divert socket
        packet_len = recvfrom(divert_sock, packet, BUFFER_SIZE, 0,
                             (struct sockaddr *)&sin, &sin_len);
        
        if (packet_len == -1) {
            perror("recvfrom");
            continue;
        }
        
        // Parse IP header
        struct ip *ip_hdr = (struct ip *)packet;
        
        // Check if it's an ICMP packet (protocol number 1)
        if (ip_hdr->ip_p == 1) {
            // Check if it's incoming 
            
            printf("Blocked incoming ICMP packet from %s to %s\n",
                   inet_ntoa(ip_hdr->ip_src),
                   inet_ntoa(ip_hdr->ip_dst));
            
            // Drop the packet 
            continue;
        }
        
        // Reinject all non-ICMP packets
        if (sendto(divert_sock, packet, packet_len, 0,
                  (struct sockaddr *)&sin, sin_len) == -1) {
            perror("sendto");
        }
    }
    
    close(divert_sock);
    return 0;
}