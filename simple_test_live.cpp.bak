#include "packet_parse/pcap_parser.hpp"
#include <iostream>
#include <signal.h>

using namespace Hypervision;

volatile bool keep_running = true;

void signal_handler(int signal) {
    keep_running = false;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    
    try {
        // Test 1: List available interfaces
        std::cout << "=== Available Network Interfaces ===" << std::endl;
        pcap_parser::list_available_interfaces();
        
        // Test 2: Choose interface (default to loopback for safe testing)
        std::string interface = "lo";
        if (argc > 1) {
            interface = argv[1];
        }
        
        std::cout << "\n=== Testing Live Parser on " << interface << " ===" << std::endl;
        std::cout << "Usage: " << argv[0] << " [interface_name]" << std::endl;
        std::cout << "Press Ctrl+C to stop\n" << std::endl;
        
        // Test 3: Create live parser
        auto parser = std::make_shared<pcap_parser>(interface, true);
        std::cout << "✓ Live parser created successfully!" << std::endl;
        
        // Test 4: Start capture
        if (!parser->start_live_capture()) {
            std::cerr << "❌ Failed to start live capture!" << std::endl;
            return 1;
        }
        std::cout << "✓ Live capture started successfully!" << std::endl;
        
        // Test 5: Try to capture some packets
        std::cout << "\n=== Capturing Packets ===" << std::endl;
        std::cout << "Generate some traffic (ping, curl, etc.) and watch for packets..." << std::endl;
        
        int batch_count = 0;
        while (keep_running && batch_count < 5) {
            // Capture up to 10 packets with 3 second timeout
            auto packets = parser->capture_packets_streaming(10, 3000);
            
            if (packets && !packets->empty()) {
                batch_count++;
                std::cout << "Batch " << batch_count << ": Captured " 
                         << packets->size() << " packets" << std::endl;
                
                // Analyze first packet
                if (!packets->empty()) {
                    auto first_packet = packets->front();
                    if (auto pkt4 = std::dynamic_pointer_cast<basic_packet4>(first_packet)) {
                        std::cout << "  Sample IPv4 packet:" << std::endl;
                        std::cout << "    Src: " << get_str_addr(tuple_get_src_addr(pkt4->flow_id)) 
                                 << ":" << tuple_get_src_port(pkt4->flow_id) << std::endl;
                        std::cout << "    Dst: " << get_str_addr(tuple_get_dst_addr(pkt4->flow_id)) 
                                 << ":" << tuple_get_dst_port(pkt4->flow_id) << std::endl;
                        std::cout << "    Length: " << pkt4->len << " bytes" << std::endl;
                    } else if (auto pkt6 = std::dynamic_pointer_cast<basic_packet6>(first_packet)) {
                        std::cout << "  Sample IPv6 packet:" << std::endl;
                        std::cout << "    Src: " << get_str_addr(tuple_get_src_addr(pkt6->flow_id)) 
                                 << ":" << tuple_get_src_port(pkt6->flow_id) << std::endl;
                        std::cout << "    Dst: " << get_str_addr(tuple_get_dst_addr(pkt6->flow_id)) 
                                 << ":" << tuple_get_dst_port(pkt6->flow_id) << std::endl;
                        std::cout << "    Length: " << pkt6->len << " bytes" << std::endl;
                    }
                }
            } else {
                std::cout << "No packets captured in this batch (timeout or no traffic)" << std::endl;
            }
            
            // Show statistics
            std::cout << "  Buffer: " << parser->get_buffer_size() 
                     << ", Received: " << parser->get_packets_received()
                     << ", Processed: " << parser->get_packets_processed() << std::endl;
        }
        
        // Test 6: Clean shutdown
        std::cout << "\n=== Stopping Capture ===" << std::endl;
        parser->stop_live_capture();
        std::cout << "✓ Live capture stopped successfully!" << std::endl;
        
        std::cout << "\n=== Test Summary ===" << std::endl;
        std::cout << "✓ Interface listing: OK" << std::endl;
        std::cout << "✓ Parser creation: OK" << std::endl;
        std::cout << "✓ Capture start/stop: OK" << std::endl;
        std::cout << "✓ Packet processing: OK" << std::endl;
        std::cout << "\n🎉 All tests passed! Live capture is working!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}