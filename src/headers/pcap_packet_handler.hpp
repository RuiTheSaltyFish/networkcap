#pragma once
#include <pcap.h>
#include <string>
#include <iostream>
#include <fmt/format.h>
#include <fmt/core.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include "packet_dataclass.hpp"
#include "net_header.hpp"

#pragma comment(lib, "ws2_32.lib")


class PcapDataHandler{
    public:
        inline static std::vector<PacketInfo> allPacket;
        static void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
             if (pkthdr->len < 64) {
                return;
             }

             EthernetHeader  *ethHeader = (struct EthernetHeader *)packet;
             std::string etherTypeString = fmt::format("0x{:04X}", ntohs(ethHeader->ether_type));  
             
             if(etherTypeString == ETHERTYPE_IPV4){
                IPV4Header* ipv4hdr = (struct IPV4Header*)(packet + sizeof(struct EthernetHeader));
                int protocol = static_cast<int>(ipv4hdr->protocol);
                TCPHeader* tcphdr = (struct TCPHeader*)(packet + sizeof(struct EthernetHeader) + sizeof(IPV4Header));
                std::string ipv4Saddr = formatIPv4String(ipv4hdr->saddr);
                std::string ipv4Daddr = formatIPv4String(ipv4hdr->daddr);
                int destPort = ntohs(tcphdr->destination_port);
                int srcPort = ntohs(tcphdr->source_port);
                if(protocol == TCP){
                    const unsigned char* payload = packet + sizeof(struct EthernetHeader) + sizeof(struct IPV4Header) + sizeof(struct TCPHeader);
                    int headerSize = sizeof(struct EthernetHeader) + sizeof(struct IPV4Header) + sizeof(struct TCPHeader);
                    PcapDataHandler::allPacket.push_back(PacketInfo(ipv4Saddr,ipv4Daddr,
                                                                    protocolToSTR(protocol),
                                                                    std::to_string(srcPort),
                                                                    std::to_string(destPort),
                                                                    payload,
                                                                    pkthdr->len - headerSize));
                }
                
                if(protocol == UDP){
                    const unsigned char* payload = packet + sizeof(struct EthernetHeader) + sizeof(struct IPV4Header) + sizeof(struct UDPHeader);
                    int headerSize = sizeof(struct EthernetHeader) + sizeof(struct IPV4Header) + sizeof(struct UDPHeader);
                    PcapDataHandler::allPacket.push_back(PacketInfo(ipv4Saddr,ipv4Daddr,
                                                                    protocolToSTR(protocol),
                                                                    std::to_string(srcPort),
                                                                    std::to_string(destPort),
                                                                    payload,
                                                                    pkthdr->len - headerSize
                                                                    ));
                }
             }

             if(etherTypeString == ETHERTYPE_IPV6){
                IPV6Header* ipv6hdr = (struct IPV6Header*)(packet + sizeof(struct EthernetHeader));
                int nheader = ipv6hdr->nextHeader;
                std::string sourceAddressStr = formatIPv6String(ipv6hdr->sourceAddress);
                std::string destinationAddressStr = formatIPv6String(ipv6hdr->destinationAddress);
                if(nheader == TCP){
                    int headerSize = sizeof(struct EthernetHeader) + sizeof(struct IPV6Header) + sizeof(struct TCPHeader);
                    const unsigned char* payload = packet + 
                                                  sizeof(struct EthernetHeader) +  
                                                  sizeof(struct IPV4Header) + 
                                                  sizeof(struct TCPHeader);

                    
                    TCPHeader* tcphdr = (struct TCPHeader*)(packet + 14 + sizeof(IPV6Header));
                    int destPort = ntohs(tcphdr->destination_port);
                    int srcPort = ntohs(tcphdr->source_port);
                    int protocol = ipv6hdr->nextHeader;
                    PcapDataHandler::allPacket.push_back(PacketInfo(sourceAddressStr,destinationAddressStr,
                                                                    protocolToSTR(protocol),
                                                                    std::to_string(srcPort),
                                                                    std::to_string(destPort),
                                                                    payload,
                                                                    pkthdr->len - headerSize
                                                                    )); 
                } 
             }    
        }

        private:
            static std::string formatIPv4String(uint32_t addr){
                uint8_t sbyte1 = (addr >> 24) & 0xFF;
                uint8_t sbyte2 = (addr >> 16) & 0xFF;
                uint8_t sbyte3 = (addr >> 8) & 0xFF;
                uint8_t sbyte4 = addr & 0xFF;
                std::string ipv4addr = fmt::format("{}.{}.{}.{}", sbyte4, sbyte3, sbyte2, sbyte1);
                return ipv4addr;
            };
            static std::string formatIPv6String(struct IPv6Address addr){
                std::string ipv6addr = fmt::format("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                                                ntohs(addr.segments[0]),
                                                ntohs(addr.segments[1]),
                                                ntohs(addr.segments[2]),
                                                ntohs(addr.segments[3]),
                                                ntohs(addr.segments[4]),
                                                ntohs(addr.segments[5]),
                                                ntohs(addr.segments[6]),
                                                ntohs(addr.segments[7]));

                return ipv6addr;
            };
            static std::string protocolToSTR(int protocol){
                if(protocol == TCP ){
                    return "TCP";
                }

                if(protocol == UDP){
                    return "UDP";
                }

                if(protocol == ICMP){
                    return "ICMP";
                }
                return  std::to_string(protocol);
            };
};
