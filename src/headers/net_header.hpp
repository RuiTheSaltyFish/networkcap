#pragma once

#include <array>
//IPV4
#define ETHERTYPE_IPV4 "0x0800"
//IPV6
#define ETHERTYPE_IPV6 "0x86DD"
#define ARP "0x0806"
//NET Protocol
#define ICMP 1
#define TCP 6
#define UDP 17
#define IPV6 41
#define OSPF 89
#define SCTP 132


static struct EthernetHeader  {
        uint8_t h_dest[6];
        uint8_t h_source[6];
        uint16_t ether_type;
}ethH;

struct UDPHeader {
    uint16_t sourcePort;       // 源端口号
    uint16_t destPort;         // 目标端口号
    uint16_t length;           // UDP数据包长度
    uint16_t checksum;         // 校验和
};

struct IPV4Header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl:4;      // IP头部长度（32位字的数量）
    uint8_t version:4;  // IP版本（4）
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version:4;  // IP版本（4）
    uint8_t ihl:4;      // IP头部长度（32位字的数量）
#endif
    uint8_t tos;         // 服务类型
    uint16_t tot_len;    // 数据包的总长度（包括IP头部和有效载荷）
    uint16_t id;         // 标识
    uint16_t frag_off;   // 分段偏移字段
    uint8_t ttl;         // 存活时间
    uint8_t protocol;    // 协议（如TCP、UDP、ICMP）
    uint16_t check;      // 头部校验和
    uint32_t saddr;      // 源IP地址
    uint32_t daddr;      // 目标IP地址
};

struct IPv6Address {
    std::array<uint16_t, 8> segments;
};

struct IPV6Header {
    uint32_t version_trafficClass_flowLabel; // 4位版本 + 8位流量類別 + 20位流標籤
    uint16_t payloadLength;
    uint8_t nextHeader;
    uint8_t hopLimit;
    IPv6Address sourceAddress;
    IPv6Address destinationAddress;
};

struct TCPHeader {
    uint16_t source_port;      // 源端口
    uint16_t destination_port; // 目标端口
    uint32_t sequence_number;  // 序列号
    uint32_t acknowledgment_number; // 确认号
    uint8_t data_offset;       // 数据偏移 (header length)
    uint8_t flags;             // 标志位
    uint16_t window;           // 窗口大小
    uint16_t checksum;         // 校验和
    uint16_t urgent_pointer;   // 紧急指针
    // 可选字段和数据（可变长度）
};
