#pragma once
#include <string>
class PacketInfo
{
public:
    PacketInfo(std::string src, std::string dest, std::string protocol, std::string srcPort,std::string destPort,
               const unsigned char *data, int dataLen)
        : srcIp(src), destIp(dest), protocol(protocol), srcPort(srcPort),destPort(destPort), data(data), dataLen(dataLen){};

    std::string get_source_address() const
    {
        return this->srcIp;
    };

    std::string get_destination_address() const
    {
        return this->destIp;
    };

    std::string get_protocol() const
    {
        return this->protocol;
    };

    std::string get_sport() const
    {
        return this->srcPort;
    };
    std::string get_dport() const
    {
        return this->destPort;
    };    
    const unsigned char *get_data() const
    {
        return this->data;
    };
    bool get_select_state() const
    {
        return this->selected;
    };
    void set_select_state(bool state)
    {
        this->selected = state;
    };
    bool get_tcp_flags() const
    {
        return this->selected;
    };
    int get_data_len()
    {
        return this->dataLen;
    }
    void set_tcp_flage(std::string flag)
    {
        this->tcpFlag = flag;
    };

private:
    std::string srcIp;
    std::string destIp;
    std::string protocol;
    std::string srcPort;
    std::string destPort;
    const unsigned char *data;
    int dataLen;
    std::string tcpFlag;
    bool selected = false;
};