#pragma once

#include "../common.hpp"
#include "pcpp_common.hpp"
#include "packet_basic.hpp"
#include "packet_info.hpp"
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <thread>

using namespace std;

namespace Hypervision {

class pcap_parser final {
private:
    // Input mode selection
    enum InputMode { FILE_MODE, LIVE_MODE };
    InputMode input_mode;
    
    // Existing file-based members
    const string target_file_path;
    shared_ptr<pcpp::IPcapDevice::PcapStats> p_parse_state;
    shared_ptr<pcpp::RawPacketVector> p_raw_packet;
    shared_ptr<pcpp::PcapFileReaderDevice> p_pcpp_file_reader;
    shared_ptr<vector<shared_ptr<basic_packet>>> p_parse_result;

    // NEW: Live capture members
    string interface_name;
    shared_ptr<pcpp::PcapLiveDevice> p_pcpp_live_device;
    
    // Streaming packet buffer
    mutable std::mutex packet_buffer_mutex;
    std::queue<pcpp::RawPacket*> packet_buffer;
    std::condition_variable buffer_condition;
    std::atomic<bool> capture_running{false};
    std::atomic<bool> stop_requested{false};
    size_t max_buffer_size = 100000;
    
    // Packet statistics
    std::atomic<size_t> packets_received{0};
    std::atomic<size_t> packets_processed{0};

public:
    // Existing file-based methods
    auto parse_raw_packet(size_t num_to_parse=-1) -> decltype(p_raw_packet);
    auto parse_basic_packet_fast(size_t multiplex=16) -> decltype(p_parse_result);
    void type_statistic(void) const;

    // NEW: Live capture methods
    bool start_live_capture();
    void stop_live_capture();
    auto capture_packets_streaming(size_t max_packets = 10000, size_t timeout_ms = 1000) -> decltype(p_parse_result);
    
    // Utility methods
    static void list_available_interfaces();
    size_t get_buffer_size() const;
    size_t get_packets_received() const { return packets_received; }
    size_t get_packets_processed() const { return packets_processed; }

    // Constructors
    pcap_parser(const pcap_parser &) = delete;
    pcap_parser & operator=(const pcap_parser &) = delete;
    virtual ~pcap_parser();

    // Existing file constructor
    explicit pcap_parser(const string & file_path);
    
    // NEW: Live capture constructor
    explicit pcap_parser(const string & interface_name, bool live_mode);

    // Existing getters (declarations only - implementations in .cpp)
    auto inline get_raw_packet_vector() const -> const decltype(p_raw_packet);
    auto inline get_basic_packet_rep() const -> const decltype(p_parse_result);
    auto inline get_parse_state() -> const decltype(p_parse_state);

private:
    // NEW: Live capture callback
    static void on_packet_arrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);
    
    // NEW: Convert raw packet buffer to basic packets
    auto process_raw_packet_buffer(const std::vector<pcpp::RawPacket*>& raw_packets, size_t multiplex=16) -> decltype(p_parse_result);
};

}