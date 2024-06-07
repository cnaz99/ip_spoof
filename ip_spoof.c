#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

#define PACKET_SIZE 64
#define LOG_FILE "/var/log/ip_spoof.log"

// Define the IP header struct
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4; // IP header length and version
    unsigned char      iph_tos;              // Type of service
    unsigned short int iph_len;              // IP Packet length (data + header)
    unsigned short int iph_ident;            // Identification
    unsigned short int iph_flag:3, iph_offset:13; // Fragmentation flags
    unsigned char      iph_ttl;              // Time to Live
    unsigned char      iph_protocol;         // Protocol type
    unsigned short int iph_chksum;           // IP datagram checksum
    struct  in_addr    iph_sourceip;         // Source IP address
    struct  in_addr    iph_destip;           // Destination IP address
};

// Calculate the checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void create_ip_header(struct ipheader *iph, const char *source_ip, const char *dest_ip) {
    iph->iph_ihl = 5; // Header length
    iph->iph_ver = 4;  // IPv4
    iph->iph_tos = 0; // Type of service
    iph->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmphdr));
    iph->iph_ident = htons(54321); // ID of this packet
    iph->iph_offset = 0;
    iph->iph_ttl = 255; // Time to live
    iph->iph_protocol = IPPROTO_ICMP; // Protocol
    iph->iph_chksum = 0; // Initial checksum
    iph->iph_sourceip.s_addr = inet_addr(source_ip); // Source IP
    iph->iph_destip.s_addr = inet_addr(dest_ip); // Destination IP

    iph->iph_chksum = checksum((unsigned short *)iph, sizeof(struct ipheader));
}

void create_icmp_header(struct icmphdr *icmph) {
    icmph->type = ICMP_ECHO; // ICMP echo request
    icmph->code = 0; // Code
    icmph->un.echo.id = 0; // ID
    icmph->un.echo.sequence = 0; // Sequence number
    icmph->checksum = 0;
    icmph->checksum = checksum((unsigned short *)icmph, sizeof(struct icmphdr));
}

void daemonize() {
    pid_t pid;

    // Fork off the parent process
    pid = fork();

    // An error occurred
    if (pid < 0)
        exit(EXIT_FAILURE);

    // Success: Let the parent terminate
    if (pid > 0)
        exit(EXIT_SUCCESS);

    // On success: The child process becomes session leader
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    // Catch, ignore and handle signals
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    // Fork off for the second time
    pid = fork();

    // An error occurred
    if (pid < 0)
        exit(EXIT_FAILURE);

    // Success: Let the parent terminate
    if (pid > 0)
        exit(EXIT_SUCCESS);

    // Set new file permissions
    umask(0);

    // Change the working directory to the root directory
    // or another appropriated directory
    chdir("/");

    // Close all open file descriptors
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }

    // Open the log file
    open(LOG_FILE, O_RDWR | O_CREAT | O_APPEND, 0600);
}

void log_message(const char *message) {
    int fd = open(LOG_FILE, O_WRONLY | O_APPEND);
    if (fd < 0) return;

    time_t now = time(NULL);
    char buf[256];
    snprintf(buf, sizeof(buf), "%s: %s\n", ctime(&now), message);
    write(fd, buf, strlen(buf));
    close(fd);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <source_ip> <dest_ip> <count>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *source_ip = argv[1];
    const char *dest_ip = argv[2];
    int count = atoi(argv[3]);

    daemonize();
    log_message("Daemon started");

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket");
        log_message("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    char packet[PACKET_SIZE];
    struct ipheader *iph = (struct ipheader *)packet;
    struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct ipheader));

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);

    int i;
    for (i = 0; i < count; i++) {
        memset(packet, 0, PACKET_SIZE);

        create_ip_header(iph, source_ip, dest_ip);
        create_icmp_header(icmph);

        char log_buf[256];
        snprintf(log_buf, sizeof(log_buf), "Sending packet %d from %s to %s", i + 1, source_ip, dest_ip);
        log_message(log_buf);

        if (sendto(sockfd, packet, sizeof(struct ipheader) + sizeof(struct icmphdr), 0,
                   (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto");
            log_message("Packet send failed");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        sleep(1);
    }

    close(sockfd);
    log_message("Daemon finished");
    return 0;
}
