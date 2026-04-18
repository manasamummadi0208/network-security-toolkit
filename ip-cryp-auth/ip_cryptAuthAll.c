 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <netinet/ip.h>
 #include <arpa/inet.h>
 #include <errno.h>
 #include <openssl/md5.h>
 
 #define BUFSIZE 65535
 #define MAXKEY  64          /* enough for lab */
 
 typedef struct        /* very small RC4 core */
 {
     unsigned char S[256];
     unsigned int i, j;
 } RC4_CTX;
 
 static void rc4_init (RC4_CTX *c, const unsigned char *k, int klen)
 {
     for (int i = 0; i < 256; ++i) c->S[i] = (unsigned char)i;
     c->i = c->j = 0;
     int j = 0;
     for (int i = 0; i < 256; ++i)
     {
         j = (j + c->S[i] + k[i % klen]) & 0xff;
         unsigned char t = c->S[i]; c->S[i] = c->S[j]; c->S[j] = t;
     }
 }
 
 static void rc4_crypt (RC4_CTX *c, unsigned char *d, int len)
 {
     for (int k = 0; k < len; ++k)
     {
         c->i = (c->i + 1) & 0xff;
         c->j = (c->j + c->S[c->i]) & 0xff;
         unsigned char t = c->S[c->i]; c->S[c->i] = c->S[c->j]; c->S[c->j] = t;
         unsigned char rnd = c->S[(c->S[c->i] + c->S[c->j]) & 0xff];
         d[k] ^= rnd;
     }
 }
 
 static unsigned short ip_checksum (unsigned short *buf, int nwords)
 {
     unsigned long sum = 0;
     while (nwords--) { sum += *buf++;     if (sum & 0xffff0000) sum = (sum & 0xffff) + (sum >> 16); }
     return (unsigned short)(~sum);
 }
 
 int main (int argc, char *argv[])
 {
     if (argc != 4)
     {
         fprintf(stderr, "Usage: %s <divert_port> <remote_ip> <key>\n", argv[0]);
         return 1;
     }
 
     int   PORT = atoi(argv[1]);
     char  RHOST[INET_ADDRSTRLEN];   strncpy(RHOST, argv[2], sizeof(RHOST));
     unsigned char KEY[MAXKEY];      int KLEN = strlen(argv[3]);
     if (KLEN > MAXKEY) KLEN = MAXKEY;
     memcpy(KEY, argv[3], KLEN);
 
     int s = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
     if (s < 0) { perror("socket"); return 1; }
 
     struct sockaddr_in sin = { 0 };
     sin.sin_family      = AF_INET;
     sin.sin_addr.s_addr = INADDR_ANY;
     sin.sin_port        = htons(PORT);
     if (bind(s, (struct sockaddr*)&sin, sizeof(sin)) < 0) { perror("bind"); return 1; }
 
     printf("[+] Listening on divert port %d ↔ %s\n", PORT, RHOST);
 
     unsigned char buf[BUFSIZE];
 
     while (1)
     {
         struct sockaddr_in rsin; socklen_t rlen = sizeof(rsin);
         ssize_t n = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr*)&rsin, &rlen);
         if (n <= 0) { if (errno == EINTR) continue; perror("recvfrom"); break; }
 
         struct ip *ip = (struct ip*)buf;
         int ip_hl  = ip->ip_hl << 2;
         int paylen = ntohs(ip->ip_len) - ip_hl;
         unsigned char *payload = buf + ip_hl;
 
         char SRC[INET_ADDRSTRLEN], DST[INET_ADDRSTRLEN];
         inet_ntop(AF_INET, &ip->ip_src, SRC, sizeof(SRC));
         inet_ntop(AF_INET, &ip->ip_dst, DST, sizeof(DST));
 
         printf("\n📦 Packet received: %ld bytes\n", (long)n);
 
         /* ------------------------------------------------------------ OUTGOING */
         if (strcmp(DST, RHOST) == 0)
         {
             printf("➡️  Outgoing encrypted packet to %s\n", RHOST);
 
             RC4_CTX c; rc4_init(&c, KEY, KLEN);
             rc4_crypt(&c, payload, paylen);
 
             /* build MD5(Y‖K) */
             unsigned char mdin[BUFSIZE];
             memcpy(mdin, payload, paylen);
             memcpy(mdin + paylen, KEY, KLEN);
             unsigned char md[MD5_DIGEST_LENGTH];
             MD5(mdin, paylen + KLEN, md);
 
             memcpy(payload + paylen, md, MD5_DIGEST_LENGTH);
             paylen += MD5_DIGEST_LENGTH;
 
             ip->ip_len = htons(ip_hl + paylen);
             ip->ip_sum = 0;
             ip->ip_sum = ip_checksum((unsigned short*)ip, ip_hl >> 1);
 
             sendto(s, buf, ip_hl + paylen, 0, (struct sockaddr*)&rsin, sizeof(rsin));
             printf("✅ Outgoing packet sent with encryption + MD5\n");
             fflush(stdout);
             continue;
         }
 
         /* ------------------------------------------------------------ INCOMING */
         if (strcmp(SRC, RHOST) == 0)
         {
             printf("⬅️  Incoming packet from %s\n", RHOST);
 
             if (paylen < MD5_DIGEST_LENGTH)
             {
                 fprintf(stderr, "❌ Payload < 16 bytes – drop\n");
                 continue;
             }
 
             int ylen = paylen - MD5_DIGEST_LENGTH;
             unsigned char *Y = payload;
             unsigned char *Z = payload + ylen;
 
             unsigned char mdin[ylen + KLEN];
             memcpy(mdin, Y, ylen);
             memcpy(mdin + ylen, KEY, KLEN);
             unsigned char md[MD5_DIGEST_LENGTH];
             MD5(mdin, ylen + KLEN, md);
 
             if (memcmp(md, Z, MD5_DIGEST_LENGTH) != 0)
             {
                 fprintf(stderr, "❌ MD5 authentication failed. Dropping packet.\n");
                 continue;
             }
 
             printf("✅ MD5 check passed. Decrypting...\n");
 
             RC4_CTX c; rc4_init(&c, KEY, KLEN);
             rc4_crypt(&c, Y, ylen);
 
             ip->ip_len = htons(ip_hl + ylen);
             ip->ip_sum = 0;
             ip->ip_sum = ip_checksum((unsigned short*)ip, ip_hl >> 1);
 
             sendto(s, buf, ip_hl + ylen, 0, (struct sockaddr*)&rsin, sizeof(rsin));
             printf("✅ Decrypted & forwarded packet\n");
             fflush(stdout);
             continue;
         }
 
         /* --------------------------------------------------------- OTHERS */
         sendto(s, buf, n, 0, (struct sockaddr*)&rsin, sizeof(rsin));
         printf("🔁 Forwarded unrelated packet\n");
         fflush(stdout);
     }
 
     close(s);
     return 0;
 }
 