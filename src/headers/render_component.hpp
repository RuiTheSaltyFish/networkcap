#pragma once
#include <vector>
#include "packet_dataclass.hpp"
#include "imgui.h"
#include <fmt/format.h>
#include <fmt/core.h>
#include <thread>
#include <string>
#include <iostream>
#include "pcapturer.hpp"


class RenderComponent{
    public:
     inline static int dataSelected = -1;
     inline static unsigned char* data;
     inline static bool ableStart = true;
     inline static int deviceSelected = 0;
     inline static char inputFilter[256] = "";
     inline static bool bpfCompileResult = true;
     static void render_capture_table(std::vector<PacketInfo> packetData){
        ImGui::Begin("Captured List",nullptr,ImGuiWindowFlags_NoCollapse );
        ImGui::BeginTable("Capture", 5);
        ImGui::TableSetupColumn("Source IP");
        ImGui::TableSetupColumn("Destination IP");
        ImGui::TableSetupColumn("Protocol");
        ImGui::TableSetupColumn("Source Port");
        ImGui::TableSetupColumn("Destination Port");
        ImGui::TableHeadersRow();   
        for (size_t i = packetData.size(); i-- > 0;) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            bool rowSelected = false;
             if(dataSelected == i){
                rowSelected = true;
             }
             ImGui::PushID(static_cast<int>(i));
             if(ImGui::Selectable(packetData[i].get_source_address().c_str(),rowSelected,ImGuiSelectableFlags_SpanAllColumns)){
                dataSelected = i;
                const unsigned char* selectedData = packetData[dataSelected].get_data();
                if(data){
                    delete[] data;
                }
                data =  new unsigned char[packetData[dataSelected].get_data_len()];
                std::memcpy(data, selectedData, packetData[dataSelected].get_data_len());
               
            }
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::Text(packetData[i].get_destination_address().c_str());
            ImGui::TableNextColumn();
            ImGui::Text(packetData[i].get_protocol().c_str());
            ImGui::TableNextColumn();
            ImGui::Text(packetData[i].get_sport().c_str());
            ImGui::TableNextColumn();
            ImGui::Text(packetData[i].get_dport().c_str());
        }
        
        
        ImGui::EndTable();
        ImGui::End();
        ImGui::Begin("Data Text",nullptr,ImGuiWindowFlags_NoCollapse);
        if(packetData.size() > 0){
            if(data != nullptr){
                std::string strData(reinterpret_cast<char*>(data), packetData[dataSelected].get_data_len());
                ImGui::Text(strData.c_str());
            }                 
        }
        ImGui::End();  
    }
    static void render_card_selection(Pcapturer* pcapc){
        std::vector<std::string> netcardList = pcapc->get_devices_list();
        ImGui::Begin("Network Card",nullptr,ImGuiWindowFlags_NoCollapse);
        ImGui::Columns(1);
        for(size_t i=0;i<netcardList.size();++i){
            if(ImGui::Selectable(netcardList[i].c_str(),deviceSelected == i)){
                 deviceSelected = i;
                 pcapc->select_net_card(static_cast<int>(i));
            }
            ImGui::NextColumn();
        }
        ImGui::End(); 
    }
    static void render_control_button(Pcapturer* pcapc){
        ImGui::Begin("Control Panel",nullptr,ImGuiWindowFlags_NoCollapse);
        ImGui::Text(fmt::format("Selected Devices : {}",deviceSelected+1).c_str());\


        ImGui::InputText(": Filter Condition", inputFilter, sizeof(inputFilter));
        if (bpfCompileResult == false) {
            ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Invalid Filter Expression");
        }
        if(!ableStart){
           ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
           ImGui::Button("Running");
           ImGui::PopStyleColor();  
        }else{
            if (ImGui::Button("Start Sniff")) {
                if(ableStart & pcapc->selectedNetCard != nullptr){
                    pcapc->set_active_device();
                    bpfCompileResult = pcapc->compile_bpf(inputFilter);
                    if(bpfCompileResult){
                       ableStart = false;
                    }                    
                }      
            }   
        }
        
        
        ImGui::SameLine();

        if(ableStart){
           ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
           ImGui::Button("Stop Sniff");
           ImGui::PopStyleColor();  
        }else{
            if (ImGui::Button("Stop Sniff")) {
                if(!ableStart){
                    pcapc->stop_sniff();
                    ableStart = true;
                }      
            }   
        } // Buffer to store input text
        ImGui::SameLine();
        if(ableStart){
            ImGui::Text("Status : WAITING");
        }else{
            ImGui::Text("Status : SNIFFING");
        }
        ImGui::SameLine();

        if(ImGui::Button("Clear")){
            PcapDataHandler::allPacket.clear();
        }
        
        ImGui::End(); 
    }
};

