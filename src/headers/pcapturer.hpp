#pragma once
#include <pcap.h>
#include <iostream>
#include <fmt/core.h>
#include <fmt/format.h>
#include <thread>
#include <vector>
#include <cstdlib>
#include "pcap_packet_handler.hpp"
#include "custome_exceptions.hpp"
//Error Code
//101:Devices Not Found;

class Pcapturer{
    public:
        pcap_if_t *selectedNetCard = nullptr;
        void initPcap(){
            try{
                memset(&filter, 0, sizeof(struct bpf_program));
                find_device();
                select_net_card(0);
            }catch(const NetworkCardNotFoundException& ex){
                std::exit(EXIT_FAILURE);
            }
        }
        void set_active_device(){
            if((activeCardHandler = pcap_open_live(
                selectedNetCard->name,
                65536,
                1,
                0,
                errbuf 
             ))==nullptr){
               std::exit(EXIT_FAILURE);
            }
        }
        void start_sniff_loop(){
            std::thread sniffThread(pcap_loop, activeCardHandler, 0, PcapDataHandler::packet_handler, nullptr);
            sniffThread.detach();
        }
        void stop_sniff(){
            pcap_breakloop(activeCardHandler);
        }
        std::vector<std::string> get_devices_list(){
            int counter = 0;
            std::vector<std::string> netCardList;
            for(pcap_if_t *d = allNetCards;d;d=d->next){
                ++counter;
                if(d->description){
                    netCardList.push_back(fmt::format("{} : {}",counter,d->description));
                }
            }
            return netCardList;
        }
        void select_net_card(int num){
                int counter;
                for (selectedNetCard = allNetCards,counter=0; 
                    counter < num; 
                    selectedNetCard = selectedNetCard->next,counter++);
        };
        bool compile_bpf(const char* filterStr){
             if (pcap_compile(activeCardHandler, &filter, filterStr, 0, PCAP_NETMASK_UNKNOWN) != -1) {
                 pcap_setfilter(activeCardHandler, &filter);
                 start_sniff_loop();
                 return true;
            }else{
                return false;
            }
        }
        ~Pcapturer(){
            if(allNetCards != nullptr){
                pcap_freealldevs(allNetCards);
            }

            if(activeCardHandler != NULL){
                pcap_close(activeCardHandler);
            }
        };

       

    private:
        pcap_if_t *allNetCards = nullptr;
        pcap_t *activeCardHandler = nullptr;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program filter;
        void find_device(){
            if(pcap_findalldevs(&allNetCards,errbuf)== -1){
                 throw NetworkCardNotFoundException();
            }
        };
        pcap_if_t* get_devices(){
            return allNetCards;
        };
};