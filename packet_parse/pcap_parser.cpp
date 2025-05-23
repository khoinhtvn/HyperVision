#include "pcap_parser.hpp"

using namespace Hypervision;

// Existing file constructor
pcap_parser::pcap_parser(const string & s) : target_file_path(s), input_mode(FILE_MODE) {
    p_pcpp_file_reader = make_shared<pcpp::PcapFileReaderDevice>(s.c_str());
    if (!p_pcpp_file_reader->open()) {
        FATAL_ERROR("Fail to read target traffic file.");
    }
    p_parse_result = nullptr;
    p_raw_packet = nullptr;
    p_parse_state = make_shared<pcpp::IPcapDevice::PcapStats>();
}

// NEW: Live capture constructor
pcap_parser::pcap_parser(const string & interface_name, bool live_mode) 
    : target_file_path(""), interface_name(interface_name), input_mode(LIVE_MODE) {
    
    // Get the live device
    pcpp::PcapLiveDevice* device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_name);
    if (device == nullptr) {
        FATAL_ERROR("Cannot find network interface: " + interface_name);
    }
    
    p_pcpp_live_device = shared_ptr<pcpp::PcapLiveDevice>(device, [](pcpp::PcapLiveDevice*){});
    
    // Open device for capture
    if (!p_pcpp_live_device->open(pcpp::PcapLiveDevice::Promiscuous)) {
        FATAL_ERROR("Cannot open device " + interface_name + " for live capture");
    }
    
    p_parse_result = nullptr;
    p_raw_packet = nullptr;
    p_parse_state = make_shared<pcpp::IPcapDevice::PcapStats>();
    
    LOGF("Live capture initialized on interface: %s", interface_name.c_str());
}

pcap_parser::~pcap_parser() {
    if (input_mode == LIVE_MODE && capture_running) {
        stop_live_capture();
    }
    
    // Clean up remaining packets in buffer
    std::lock_guard<std::mutex> lock(packet_buffer_mutex);
    while (!packet_buffer.empty()) {
        delete packet_buffer.front();
        packet_buffer.pop();
    }
}

// NEW: Start live packet capture
bool pcap_parser::start_live_capture() {
    if (input_mode != LIVE_MODE) {
        FATAL_ERROR("Not in live capture mode");
        return false;
    }
    
    if (capture_running) {
        WARN("Live capture already running");
        return true;
    }
    
    stop_requested = false;
    capture_running = true;
    
    if (!p_pcpp_live_device->startCapture(on_packet_arrives, this)) {
        FATAL_ERROR("Failed to start packet capture");
        capture_running = false;
        return false;
    }
    
    LOGF("Started live packet capture on %s", interface_name.c_str());
    return true;
}

// NEW: Stop live packet capture
void pcap_parser::stop_live_capture() {
    if (!capture_running) {
        return;
    }
    
    stop_requested = true;
    p_pcpp_live_device->stopCapture();
    capture_running = false;
    
    // Notify any waiting threads
    buffer_condition.notify_all();
    
    LOGF("Stopped live packet capture on %s", interface_name.c_str());
}

// NEW: Packet arrival callback
void pcap_parser::on_packet_arrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
    pcap_parser* parser = static_cast<pcap_parser*>(cookie);
    
    if (parser->stop_requested) {
        return;
    }
    
    std::unique_lock<std::mutex> lock(parser->packet_buffer_mutex);
    
    // Drop packets if buffer is full (backpressure handling)
    if (parser->packet_buffer.size() >= parser->max_buffer_size) {
        // Drop oldest packet
        delete parser->packet_buffer.front();
        parser->packet_buffer.pop();
    }
    
    // Add new packet (make a copy since PcapPlusPlus may reuse the buffer)
    pcpp::RawPacket* packet_copy = new pcpp::RawPacket(*packet);
    parser->packet_buffer.push(packet_copy);
    parser->packets_received++;
    
    lock.unlock();
    parser->buffer_condition.notify_one();
}

// NEW: Capture packets in streaming mode
auto pcap_parser::capture_packets_streaming(size_t max_packets, size_t timeout_ms) -> decltype(p_parse_result) {
    if (input_mode != LIVE_MODE) {
        FATAL_ERROR("Not in live capture mode");
        return nullptr;
    }
    
    if (!capture_running) {
        FATAL_ERROR("Live capture not started");
        return nullptr;
    }
    
    std::vector<pcpp::RawPacket*> raw_packets;
    raw_packets.reserve(max_packets);
    
    std::unique_lock<std::mutex> lock(packet_buffer_mutex);
    
    // Wait for packets or timeout
    auto timeout_time = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    
    while (raw_packets.size() < max_packets && 
           std::chrono::steady_clock::now() < timeout_time && 
           !stop_requested) {
        
        if (packet_buffer.empty()) {
            if (buffer_condition.wait_until(lock, timeout_time) == std::cv_status::timeout) {
                break; // Timeout reached
            }
            continue;
        }
        
        // Extract packets from buffer
        while (!packet_buffer.empty() && raw_packets.size() < max_packets) {
            raw_packets.push_back(packet_buffer.front());
            packet_buffer.pop();
        }
    }
    
    lock.unlock();
    
    if (raw_packets.empty()) {
        return nullptr;
    }
    
    // Process the captured packets using existing parsing logic
    auto result = process_raw_packet_buffer(raw_packets);
    
    // Clean up raw packets
    for (auto* packet : raw_packets) {
        delete packet;
    }
    
    packets_processed += raw_packets.size();
    
    LOGF("Processed %ld packets from live capture", raw_packets.size());
    return result;
}

// NEW: Process raw packet buffer (adapted from existing parse_basic_packet_fast)
auto pcap_parser::process_raw_packet_buffer(const std::vector<pcpp::RawPacket*>& raw_packets, size_t multiplex) -> decltype(p_parse_result) {
    if (raw_packets.empty()) {
        return nullptr;
    }
    
    size_t bad_packet = 0;
    auto parse_result = make_shared<vector<shared_ptr<basic_packet>>>(raw_packets.size());
    
    const u_int32_t part_size = ceil(((double) raw_packets.size()) / ((double) multiplex));
    vector<pair<size_t, size_t>> _assign;
    for (size_t core = 0, idx = 0; core < multiplex; ++core, idx += part_size) {
        _assign.push_back({idx, min(idx + part_size, raw_packets.size())});
    }

    auto __f = [&](const size_t _start, const size_t _end, 
                   const std::vector<pcpp::RawPacket*>& _from, 
                   decltype(parse_result) _to) -> void {
        
        for (size_t i = _start; i < _end; i++) {
            const auto& __p_raw_pk = _from[i];
            unique_ptr<pcpp::Packet> p_parsed_packet(
                new pcpp::Packet(__p_raw_pk, false, pcpp::IP, pcpp::OsiModelNetworkLayer));

            pkt_addr4_t s4, d4;
            pkt_addr6_t s6, d6;
            shared_ptr<basic_packet> ptr_add = nullptr;
            pkt_code_t packet_code = 0;
            pkt_ts_t packet_time = __p_raw_pk->getPacketTimeStamp();
            pkt_port_t s_port = 0, d_port = 0;
            pkt_len_t packet_length = 0;

            auto _f_parse_udp = [&p_parsed_packet, &s_port, &d_port, &packet_code]() -> void {
                pcpp::UdpLayer* p_udp_layer = p_parsed_packet->getLayerOfType<pcpp::UdpLayer>();
                s_port = htons(p_udp_layer->getUdpHeader()->portSrc);
                d_port = htons(p_udp_layer->getUdpHeader()->portDst);
                set_pkt_type_code(packet_code, pkt_type_t::UDP);
            };

            auto _f_parse_tcp = [&p_parsed_packet, &s_port, &d_port, &packet_code]() -> void {
                pcpp::TcpLayer* p_tcp_layer = p_parsed_packet->getLayerOfType<pcpp::TcpLayer>();
                s_port = htons(p_tcp_layer->getTcpHeader()->portSrc);
                d_port = htons(p_tcp_layer->getTcpHeader()->portDst);
                if (p_tcp_layer->getTcpHeader()->synFlag) {
                    set_pkt_type_code(packet_code, pkt_type_t::TCP_SYN);
                }
                if (p_tcp_layer->getTcpHeader()->finFlag) {
                    set_pkt_type_code(packet_code, pkt_type_t::TCP_FIN);
                }
                if (p_tcp_layer->getTcpHeader()->rstFlag) {
                    set_pkt_type_code(packet_code, pkt_type_t::TCP_RST);
                }
                if (p_tcp_layer->getTcpHeader()->ackFlag) {
                    set_pkt_type_code(packet_code, pkt_type_t::TCP_ACK);
                }
            };

            auto _f_load_ipv6_addr_byte = [](const pcpp::IPv6Address& addr6) -> pkt_addr6_t {
                __pkt_addr6 __t;
                memcpy(__t.byte_rep, addr6.toBytes(), sizeof(__t));
                return __t.num_rep;
            };

            pcpp::ProtocolType type_next;
            if (p_parsed_packet->isPacketOfType(pcpp::IPv4)) {
                pcpp::IPv4Layer* p_IPv4_layer = p_parsed_packet->getLayerOfType<pcpp::IPv4Layer>();
                set_pkt_type_code(packet_code, pkt_type_t::IPv4);

                s4 = p_IPv4_layer->getSrcIPv4Address().toInt();
                d4 = p_IPv4_layer->getDstIPv4Address().toInt();
                packet_length = htons(p_IPv4_layer->getIPv4Header()->totalLength);
                p_IPv4_layer->parseNextLayer();
                if (p_IPv4_layer->getNextLayer() == nullptr) {
                    type_next = pcpp::UnknownProtocol;
                } else {
                    type_next = p_IPv4_layer->getNextLayer()->getProtocol();
                }
            } else if (p_parsed_packet->isPacketOfType(pcpp::IPv6)) {
                pcpp::IPv6Layer* p_IPv6_layer = p_parsed_packet->getLayerOfType<pcpp::IPv6Layer>();
                set_pkt_type_code(packet_code, pkt_type_t::IPv6);

                s6 = _f_load_ipv6_addr_byte(p_IPv6_layer->getSrcIPv6Address());
                d6 = _f_load_ipv6_addr_byte(p_IPv6_layer->getDstIPv6Address());
                packet_length = htons(p_IPv6_layer->getIPv6Header()->payloadLength);
                p_IPv6_layer->parseNextLayer();
                if (p_IPv6_layer->getNextLayer() == nullptr) {
                    type_next = pcpp::UnknownProtocol;
                } else {
                    type_next = p_IPv6_layer->getNextLayer()->getProtocol();
                }
            } else {
                // bad packet
                bad_packet += 1;
                (*_to)[i] = make_shared<basic_packet_bad>(packet_time);
                continue;
            }

            switch (type_next) {
            case pcpp::TCP:
                _f_parse_tcp();
                break;
            case pcpp::UDP:
                _f_parse_udp();
                break;
            case pcpp::ICMP:
                set_pkt_type_code(packet_code, pkt_type_t::ICMP);
                break;
            case pcpp::IGMP:
                set_pkt_type_code(packet_code, pkt_type_t::IGMP);
                break;
            default:
                set_pkt_type_code(packet_code, pkt_type_t::UNKNOWN);
                break;
            }

            if (test_pkt_type_code(packet_code, pkt_type_t::IPv4)) {
                ptr_add = make_shared<basic_packet4>(
                    s4, d4, s_port, d_port, packet_time, packet_code, packet_length
                );
            } else if (test_pkt_type_code(packet_code, pkt_type_t::IPv6)) {
                ptr_add = make_shared<basic_packet6>(
                    s6, d6, s_port, d_port, packet_time, packet_code, packet_length
                );
            } else {
                assert(false);
            }

            (*_to)[i] = ptr_add;
        }
    };

    vector<thread> vt;
    assert(multiplex > 0);
    for (size_t core = 0; core < multiplex; core++) {
        vt.emplace_back(__f, _assign[core].first, _assign[core].second, raw_packets, parse_result);
    }

    for (auto& t : vt)
        t.join();

    return parse_result;
}

// NEW: List available network interfaces
void pcap_parser::list_available_interfaces() {
    std::cout << "Available network interfaces:" << std::endl;
    auto& deviceList = pcpp::PcapLiveDeviceList::getInstance();
    for (auto* device : deviceList.getPcapLiveDevicesList()) {
        std::cout << "  - " << device->getName() << " (" << device->getDesc() << ")" << std::endl;
        if (device->getIPv4Address() != pcpp::IPv4Address::Zero) {
            std::cout << "    IPv4: " << device->getIPv4Address().toString() << std::endl;
        }
    }
}

size_t pcap_parser::get_buffer_size() const {
    std::lock_guard<std::mutex> lock(packet_buffer_mutex);
    return packet_buffer.size();
}

// EXISTING FILE-BASED METHODS (COMPLETE ORIGINAL CODE)
auto pcap_parser::parse_raw_packet(size_t num_to_parse) -> decltype(p_raw_packet) {
    if (input_mode != FILE_MODE) {
        FATAL_ERROR("parse_raw_packet() only available in file mode");
        return nullptr;
    }
    
    if (p_raw_packet) {
        LOG("Parsing has been done, do it again.");
    }
    p_raw_packet = make_shared<pcpp::RawPacketVector>();
    if (!p_pcpp_file_reader->getNextPackets(*p_raw_packet, num_to_parse)) {
        FATAL_ERROR("Couldn't read the first packet in the file.");
    } else {
        LOGF("Read %ld raw packet from %s.", p_raw_packet->size(), target_file_path.c_str());
    }
    return p_raw_packet;
}

auto pcap_parser::parse_basic_packet_fast(size_t multiplex) -> decltype(p_parse_result) {
    if (input_mode != FILE_MODE) {
        FATAL_ERROR("parse_basic_packet_fast() only available in file mode");
        return nullptr;
    }
    
    if (p_parse_result) {
        WARN("Packets have been parsed, do it again.");
    }
    size_t bad_packet = 0;
    p_parse_result = make_shared<vector<shared_ptr<basic_packet> > >(p_raw_packet->size());
    const u_int32_t part_size = ceil(((double) p_raw_packet->size()) / ((double) multiplex));
    vector<pair<size_t, size_t> > _assign;
    for (size_t core = 0, idx = 0; core < multiplex; ++ core, idx += part_size) {
        _assign.push_back({idx, min(idx + part_size, p_raw_packet->size())});
    }

    auto __f =  [&] (const size_t _start, const size_t _end, 
            decltype(p_raw_packet) _from, decltype(p_parse_result) _to) -> void {
        for (size_t i = _start; i < _end; i ++) {
            const auto & __p_raw_pk = (*_from).at(i);
            unique_ptr<pcpp::Packet> p_parsed_packet(
                new pcpp::Packet(__p_raw_pk, false, pcpp::IP, pcpp::OsiModelNetworkLayer));

            pkt_addr4_t s4, d4;
            pkt_addr6_t s6, d6;
            shared_ptr<basic_packet> ptr_add = nullptr;
            pkt_code_t packet_code = 0;
            pkt_ts_t packet_time = __p_raw_pk->getPacketTimeStamp();
            pkt_port_t s_port = 0, d_port = 0;
            pkt_len_t packet_length = 0;

            auto _f_parse_udp = [&p_parsed_packet, &s_port, &d_port, &packet_code] () -> void {
                pcpp::UdpLayer * p_udp_layer = p_parsed_packet->getLayerOfType<pcpp::UdpLayer>();
                s_port = htons(p_udp_layer->getUdpHeader()->portSrc);
                d_port = htons(p_udp_layer->getUdpHeader()->portDst);
                set_pkt_type_code(packet_code, pkt_type_t::UDP);
            };

            auto _f_parse_tcp = [&p_parsed_packet, &s_port, &d_port, &packet_code] () -> void {
                pcpp::TcpLayer * p_tcp_layer = p_parsed_packet->getLayerOfType<pcpp::TcpLayer>();
                s_port = htons(p_tcp_layer->getTcpHeader()->portSrc);
                d_port = htons(p_tcp_layer->getTcpHeader()->portDst);
                if (p_tcp_layer->getTcpHeader()->synFlag) {
                    set_pkt_type_code(packet_code, pkt_type_t::TCP_SYN);
                } 
                if (p_tcp_layer->getTcpHeader()->finFlag) {
                    set_pkt_type_code(packet_code, pkt_type_t::TCP_FIN);
                }
                if (p_tcp_layer->getTcpHeader()->rstFlag) {
                    set_pkt_type_code(packet_code, pkt_type_t::TCP_RST);
                } 
                if (p_tcp_layer->getTcpHeader()->ackFlag) {
                    set_pkt_type_code(packet_code, pkt_type_t::TCP_ACK);
                }
            };

            auto _f_load_ipv6_addr_byte = [] (const pcpp::IPv6Address & addr6) -> pkt_addr6_t {
                __pkt_addr6 __t;
                memcpy(__t.byte_rep, addr6.toBytes(), sizeof(__t));
                return __t.num_rep;
            };

            pcpp::ProtocolType type_next;
            if (p_parsed_packet->isPacketOfType(pcpp::IPv4)) {
                pcpp::IPv4Layer * p_IPv4_layer = p_parsed_packet->getLayerOfType<pcpp::IPv4Layer>();
                set_pkt_type_code(packet_code, pkt_type_t::IPv4);

                s4 = p_IPv4_layer->getSrcIPv4Address().toInt();
                d4 = p_IPv4_layer->getDstIPv4Address().toInt();
                packet_length = htons(p_IPv4_layer->getIPv4Header()->totalLength);
                p_IPv4_layer->parseNextLayer();
                if (p_IPv4_layer->getNextLayer() == nullptr) {
                    type_next = pcpp::UnknownProtocol;
                } else {
                    type_next = p_IPv4_layer->getNextLayer()->getProtocol();
                }
            } else if (p_parsed_packet->isPacketOfType(pcpp::IPv6)) {
                pcpp::IPv6Layer * p_IPv6_layer = p_parsed_packet->getLayerOfType<pcpp::IPv6Layer>();
                set_pkt_type_code(packet_code, pkt_type_t::IPv6);

                s6 = _f_load_ipv6_addr_byte(p_IPv6_layer->getSrcIPv6Address());
                d6 = _f_load_ipv6_addr_byte(p_IPv6_layer->getDstIPv6Address());
                packet_length = htons(p_IPv6_layer->getIPv6Header()->payloadLength);
                p_IPv6_layer->parseNextLayer();
                if (p_IPv6_layer->getNextLayer() == nullptr) {
                    type_next = pcpp::UnknownProtocol;
                } else {
                    type_next = p_IPv6_layer->getNextLayer()->getProtocol();
                }
            } else {
                // bad packet
                bad_packet += 1;
                (*_to)[i] = make_shared<basic_packet_bad>(packet_time);
                continue;
            }

            switch (type_next) {
            case pcpp::TCP:
                _f_parse_tcp();
                break;
            case pcpp::UDP:
                _f_parse_udp();
                break;
            case pcpp::ICMP:
                set_pkt_type_code(packet_code, pkt_type_t::ICMP);
                break;
            case pcpp::IGMP:
                set_pkt_type_code(packet_code, pkt_type_t::IGMP);
                break;
            default:
                set_pkt_type_code(packet_code, pkt_type_t::UNKNOWN);
                break;
            }

            if (test_pkt_type_code(packet_code, pkt_type_t::IPv4)) {
                ptr_add = make_shared<basic_packet4>(
                    s4, d4, s_port, d_port, packet_time, packet_code, packet_length
                );
            } else if (test_pkt_type_code(packet_code, pkt_type_t::IPv6)) {
                ptr_add = make_shared<basic_packet6>(
                    s6, d6, s_port, d_port, packet_time, packet_code, packet_length
                );
            } else {
                assert(false);
            }

            (*_to)[i] = ptr_add;
        }
    };

    vector<thread> vt;
    assert(multiplex > 0);
    for (size_t core = 0; core < multiplex; core ++ ) {
        vt.emplace_back(__f, _assign[core].first, _assign[core].second, p_raw_packet, p_parse_result);
    }

    for (auto & t : vt)
        t.join();

    LOGF("%ld packets representation was parsed, %ld bad packets.", p_parse_result->size(), bad_packet);
    return p_parse_result;
}

void pcap_parser::type_statistic(void) const {
    if (p_parse_result == nullptr) {
        FATAL_ERROR("Analyze packet statictics befor parse packets");
    }

    size_t bad_packet = 0;
    vector<u_int32_t> __sat(pkt_type_t::UNKNOWN + 1);
    for (auto p_bp_rep: *p_parse_result) {
        if (typeid(*p_bp_rep) != typeid(basic_packet_bad)) {
            for (uint8_t i = 0; i < pkt_type_t::UNKNOWN + 1; i ++) {
                if (test_pkt_type_code(p_bp_rep->tp, (pkt_type_t) i)) {
                    __sat[i] ++;
                }
            }
        } else {
            bad_packet ++;
        }
    }
    LOG("Display parsed packet type statistic");

    for (size_t i = 0; i <= pkt_type_t::UNKNOWN; i ++) {
        printf("[%-8s]: %d\n", type2name[i], __sat[i]);
    }
    printf("[%-8s]: %ld\n", "ALL", __sat[pkt_type_t::IPv4] + __sat[pkt_type_t::IPv6] + bad_packet);
    printf("[%-8s]: %ld\n", "BAD", bad_packet);
}

auto pcap_parser::get_raw_packet_vector() const -> const decltype(p_raw_packet) {
    if (p_raw_packet) {
        return p_raw_packet;
    } else {
        WARN("Raw packet vector acquired without initialization.");
        return nullptr;
    }
}

auto pcap_parser::get_basic_packet_rep() const -> const decltype(p_parse_result) {
    if (p_parse_result) {
        return p_parse_result;
    } else {
        WARN("Void parse results returned.");
        return nullptr;
    }
}

auto pcap_parser::get_parse_state() -> const decltype(p_parse_state) {
    if (input_mode == FILE_MODE) {
        p_pcpp_file_reader->getStatistics(*p_parse_state);
    } else {
        p_pcpp_live_device->getStatistics(*p_parse_state);
    }
    return p_parse_state;
}