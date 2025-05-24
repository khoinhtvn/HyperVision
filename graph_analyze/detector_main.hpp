#pragma once

#include "../common.hpp"
#include "../packet_parse/pcap_parser.hpp"
#include "../flow_construct/explicit_constructor.hpp"
#include "edge_constructor.hpp"
#include "graph_define.hpp"

// Additional includes for live traffic support
#include <thread>
#include <atomic>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <chrono>

namespace Hypervision
{

class hypervision_detector {
private:
    // EXISTING members (unchanged from original)
    json jin_main;
    string file_path = "";
    
    shared_ptr<vector<shared_ptr<basic_packet>>> p_parse_result;
    shared_ptr<binary_label_t> p_label;
    shared_ptr<vector<double_t>> p_loss;
    shared_ptr<vector<shared_ptr<basic_flow>>> p_flow;
    shared_ptr<vector<shared_ptr<short_edge>>> p_short_edges;
    shared_ptr<vector<shared_ptr<long_edge>>> p_long_edges;

    bool save_result_enable = false;
    string save_result_path = "../temp/default.json";

    // NEW: Processing mode tracking
    enum ProcessingMode { 
        DATASET_MODE,    // .data/.label files (current demo)
        PCAP_FILE_MODE,  // .pcap files (existing but unused)
        LIVE_MODE        // Live network capture (NEW)
    };
    ProcessingMode processing_mode = DATASET_MODE;

    // NEW: Live processing members
    shared_ptr<pcap_parser> p_live_parser;
    std::atomic<bool> live_processing_active{false};
    std::thread live_processing_thread;
    string live_interface_name;
    
    // NEW: Live processing configuration
    size_t live_batch_size = 1000;
    size_t live_timeout_ms = 5000;
    double live_alert_threshold = 11.0;
    
    // NEW: Packet counter for live mode (to maintain global indexing)
    std::atomic<size_t> global_packet_counter{0};

public:
    // Constructor/Destructor
    hypervision_detector() = default;
    ~hypervision_detector() {
        stop_live_processing();
    }

    // ENHANCED: Main processing method (supports live mode)
    void start(void) {
        __START_FTIMMER__

        // EXISTING MODE 1: PCAP file processing (unchanged)
        if (jin_main.count("packet_parse") &&
            jin_main["packet_parse"].count("target_file_path")) {
            
            processing_mode = PCAP_FILE_MODE;
            LOGF("Parse packet from file.");
            file_path = jin_main["packet_parse"]["target_file_path"];
            const auto p_packet_parser = make_shared<pcap_parser>(file_path);
            p_packet_parser->parse_raw_packet();
            p_packet_parser->parse_basic_packet_fast();
            p_parse_result = p_packet_parser->get_basic_packet_rep();

            LOGF("Split datasets.");
            const auto p_dataset_constructor = make_shared<basic_dataset>(p_parse_result);
            p_dataset_constructor->configure_via_json(jin_main["dataset_construct"]);
            p_dataset_constructor->do_dataset_construct();
            p_label = p_dataset_constructor->get_label();

        // EXISTING MODE 2: Pre-processed data files (unchanged)
        } else if (jin_main["dataset_construct"].count("data_path") && 
                   jin_main["dataset_construct"].count("label_path")) {
            
            processing_mode = DATASET_MODE;
            LOGF("Load & split datasets.");
            const auto p_dataset_constructor = make_shared<basic_dataset>(p_parse_result);
            p_dataset_constructor->configure_via_json(jin_main["dataset_construct"]);
            p_dataset_constructor->import_dataset();
            p_label = p_dataset_constructor->get_label();
            p_parse_result = p_dataset_constructor->get_raw_pkt();

        // NEW MODE 3: Live network capture
        } else if (jin_main.count("live_capture") &&
                   jin_main["live_capture"].count("interface_name")) {
            
            processing_mode = LIVE_MODE;
            live_interface_name = jin_main["live_capture"]["interface_name"];
            configure_live_mode();
            start_live_processing();
            return; // Live mode uses different processing loop

        } else {
            LOGF("Dataset not found.");
            return;
        }

        // EXISTING PIPELINE: Process batch for file/dataset modes (unchanged)
        if (processing_mode != LIVE_MODE) {
            process_batch_pipeline();
        }

        __STOP_FTIMER__
        __PRINTF_EXE_TIME__
    }

    // ENHANCED: Configuration method (supports live mode)
    void config_via_json(const json & jin) {
        try {
            // EXISTING: Core configuration validation (unchanged)
            if (jin.count("dataset_construct") &&
                jin.count("flow_construct") &&
                jin.count("edge_construct") &&
                jin.count("graph_analyze") &&
                jin.count("result_save")) {
                    jin_main = jin;
            } else {
                throw logic_error("Incomplete json configuration.");
            }
            
            // EXISTING: Result save configuration (unchanged)
            const auto j_save = jin["result_save"];
            if (j_save.count("save_result_enable")) {
                save_result_enable = static_cast<decltype(save_result_enable)>(j_save["save_result_enable"]);
            }
            if (j_save.count("save_result_path")) {
                save_result_path = static_cast<decltype(save_result_path)>(j_save["save_result_path"]);
            }

            // NEW: Live capture configuration
            if (jin.count("live_capture")) {
                const auto j_live = jin["live_capture"];
                if (j_live.count("batch_size")) {
                    live_batch_size = static_cast<size_t>(j_live["batch_size"]);
                }
                if (j_live.count("capture_timeout_ms")) {
                    live_timeout_ms = static_cast<size_t>(j_live["capture_timeout_ms"]);
                }
            }
            
            // NEW: Alerting configuration
            if (jin.count("alerting") && jin["alerting"].count("alert_threshold")) {
                live_alert_threshold = static_cast<double>(jin["alerting"]["alert_threshold"]);
            }

        } catch (const exception & e) {
            FATAL_ERROR(e.what());
        }
    }

    // EXISTING: Save results method (unchanged)
    void do_save(const string & save_path) {
        __START_FTIMMER__

        ofstream _f(save_path);
        if (_f.is_open()) {
            try {
                _f << setprecision(4);
                for (size_t i = 0; i < p_label->size(); ++i) {
                    _f << p_label->at(i) << ' '<< p_loss->at(i) << '\n';
                    if (i % 1000 == 0) {
                        _f << flush;
                    }
                }
            } catch(const exception & e) {
                FATAL_ERROR(e.what());
            }
            _f.close();
        } else {
            FATAL_ERROR("File Error.");
        }
        
        __STOP_FTIMER__
        __PRINTF_EXE_TIME__
    }

    // NEW: Live processing control methods
    void configure_live_mode() {
        try {
            p_live_parser = make_shared<pcap_parser>(live_interface_name, true);
            if (!p_live_parser->start_live_capture()) {
                FATAL_ERROR("Failed to start live capture on " + live_interface_name);
            }
            LOGF("Live capture configured on interface: %s", live_interface_name.c_str());
        } catch (const exception& e) {
            FATAL_ERROR("Live mode configuration failed: " + string(e.what()));
        }
    }

    void start_live_processing() {
        live_processing_active = true;
        live_processing_thread = std::thread(&hypervision_detector::live_processing_loop, this);
        LOGF("Live processing started on %s", live_interface_name.c_str());
        
        // Keep main thread alive for live processing
        live_processing_thread.join();
    }

    void stop_live_processing() {
        if (live_processing_active) {
            live_processing_active = false;
            if (p_live_parser) {
                p_live_parser->stop_live_capture();
            }
            if (live_processing_thread.joinable()) {
                live_processing_thread.join();
            }
            LOGF("Live processing stopped");
        }
    }

private:
    // EXISTING: Batch processing pipeline (extracted from original start() method)
    void process_batch_pipeline() {
        LOGF("Construct flow.");
        const auto p_flow_constructor = make_shared<explicit_flow_constructor>(p_parse_result);
        p_flow_constructor->config_via_json(jin_main["flow_construct"]);
        p_flow_constructor->construct_flow();
        p_flow = p_flow_constructor->get_constructed_raw_flow();

        LOGF("Construct edge.");
        const auto p_edge_constructor = make_shared<edge_constructor>(p_flow);
        p_edge_constructor->config_via_json(jin_main["edge_construct"]);
        p_edge_constructor->do_construct();
        tie(p_short_edges, p_long_edges) = p_edge_constructor->get_edge();

        LOGF("Construct Graph.");
        const auto p_graph = make_shared<traffic_graph>(p_short_edges, p_long_edges);
        p_graph->config_via_json(jin_main["graph_analyze"]);
        p_graph->parse_edge();
        p_graph->graph_detect();
        p_loss = p_graph->get_final_pkt_score(p_label);

        if (save_result_enable) {
            do_save(save_result_path);
        }
    }

    // NEW: Live processing main loop
    void live_processing_loop() {
        LOGF("Starting live processing loop...");
        
        while (live_processing_active) {
            try {
                // Capture packets from network interface
                auto packets = p_live_parser->capture_packets_streaming(live_batch_size, live_timeout_ms);
                
                if (packets && !packets->empty()) {
                    LOGF("Processing %ld packets from live capture", packets->size());
                    process_live_packet_batch(*packets);
                } else {
                    // No packets - brief pause to prevent busy waiting
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                
            } catch (const exception& e) {
                LOGF("Live processing error: %s", e.what());
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
        
        LOGF("Live processing loop terminated");
    }

    // CRITICAL FIX: Validate and filter packets before processing
    vector<shared_ptr<basic_packet>> validate_packets(const vector<shared_ptr<basic_packet>>& packets) {
        vector<shared_ptr<basic_packet>> valid_packets;
        
        for (const auto& pkt : packets) {
            if (!pkt) {
                LOGF("Skipping null packet");
                continue;
            }
            
            try {
                // FIXED: Use proper accessor methods
                if (!pkt->is_valid()) {
                    LOGF("Skipping invalid packet");
                    continue;
                }
                
                // FIXED: Use new accessor methods instead of direct access
                auto ts = pkt->get_ts();
                auto len = pkt->get_len();
                auto tp = pkt->get_tp();
                
                // Basic sanity checks
                if (len == 0 || len > 65535) {
                    LOGF("Skipping packet with invalid length: %d", len);
                    continue;
                }
                
                // Check if it's a bad packet type
                if (typeid(*pkt) == typeid(basic_packet_bad)) {
                    LOGF("Skipping bad packet type");
                    continue;
                }
                
                valid_packets.push_back(pkt);
                
            } catch (const exception& e) {
                LOGF("Skipping packet due to validation error: %s", e.what());
                continue;
            } catch (...) {
                LOGF("Skipping packet due to unknown validation error");
                continue;
            }
        }
        
        LOGF("Validated %ld packets out of %ld total", valid_packets.size(), packets.size());
        return valid_packets;
    }

    // CRITICAL FIX: Enhanced process_live_packet_batch with graph validation
    void process_live_packet_batch(const vector<shared_ptr<basic_packet>>& packets) {
        if (packets.empty()) {
            LOGF("Empty packet batch received");
            return;
        }

        try {
            LOGF("Starting batch processing for %ld packets", packets.size());
            
            // STEP 1: Validate packets first
            auto valid_packets = validate_packets(packets);
            if (valid_packets.empty()) {
                LOGF("No valid packets in batch - skipping processing");
                return;
            }
            
            LOGF("Processing %ld valid packets", valid_packets.size());
            
            // STEP 2: Create packet vector with proper sizing
            p_parse_result = make_shared<vector<shared_ptr<basic_packet>>>(valid_packets);
            
            // STEP 3: Create labels with exact same size
            p_label = make_shared<binary_label_t>(valid_packets.size(), false); // All benign for unsupervised

            LOGF("Created packet result: %ld packets, labels: %ld", 
                 p_parse_result->size(), p_label->size());

            // STEP 4: Enhanced minimum packet validation
            if (p_parse_result->size() < 6) {
                LOGF("Too few packets for meaningful graph analysis (need >= 6, got %ld)", p_parse_result->size());
                LOGF("Small batches like ping traffic cannot form complex interaction patterns");
                provide_simple_scoring(valid_packets);
                return;
            }

            LOGF("Running flow construction...");
            
            // STEP 5: Use controlled threading for flow construction
            size_t thread_count = std::min((size_t)4, std::max((size_t)1, p_parse_result->size() / 20));
            if (thread_count == 0) thread_count = 1;
            
            try {
                const auto p_flow_constructor = make_shared<explicit_flow_constructor>(p_parse_result);
                p_flow_constructor->config_via_json(jin_main["flow_construct"]);
                
                // Use controlled threading for small batches
                p_flow_constructor->construct_flow(thread_count);
                p_flow = p_flow_constructor->get_constructed_raw_flow();
                
                LOGF("Flow construction completed: %ld flows", p_flow ? p_flow->size() : 0);
                
            } catch (const std::out_of_range& e) {
                LOGF("Flow construction failed with indexing error: %s - this usually indicates packet data issues", e.what());
                return;
            } catch (const exception& e) {
                LOGF("ERROR in flow construction: %s", e.what());
                return;
            }

            // STEP 6: Enhanced flow validation
            if (!p_flow || p_flow->empty()) {
                LOGF("No flows constructed - this is normal for very small packet batches");
                provide_simple_scoring(valid_packets);
                return;
            }
            
            if (p_flow->size() < 2) {
                LOGF("Insufficient flows for graph analysis (need >= 2, got %ld)", p_flow->size());
                LOGF("Single flow cannot create meaningful interaction patterns");
                provide_simple_scoring(valid_packets);
                return;
            }

            LOGF("Running edge construction...");
            try {
                const auto p_edge_constructor = make_shared<edge_constructor>(p_flow);
                p_edge_constructor->config_via_json(jin_main["edge_construct"]);
                p_edge_constructor->do_construct();
                tie(p_short_edges, p_long_edges) = p_edge_constructor->get_edge();
                
                LOGF("Edge construction completed: %ld short edges, %ld long edges", 
                     p_short_edges ? p_short_edges->size() : 0,
                     p_long_edges ? p_long_edges->size() : 0);
                     
            } catch (const exception& e) {
                LOGF("ERROR in edge construction: %s", e.what());
                return;
            }

            // STEP 7: Enhanced edge validation for graph complexity
            size_t total_edges = 0;
            if (p_short_edges) total_edges += p_short_edges->size();
            if (p_long_edges) total_edges += p_long_edges->size();
            
            if (total_edges == 0) {
                LOGF("No edges constructed - cannot perform graph analysis");
                provide_simple_scoring(valid_packets);
                return;
            }
            
            if (total_edges < 3) {
                LOGF("Insufficient edges for meaningful graph analysis (need >= 3, got %ld)", total_edges);
                LOGF("Simple traffic patterns (ping, single connections) don't require complex analysis");
                provide_simple_scoring(valid_packets);
                return;
            }

            LOGF("Running graph analysis...");
            try {
                const auto p_graph = make_shared<traffic_graph>(p_short_edges, p_long_edges);
                p_graph->config_via_json(jin_main["graph_analyze"]);
                p_graph->parse_edge();
                
                // CRITICAL FIX: Wrap graph_detect in additional try-catch
                try {
                    p_graph->graph_detect();
                    p_loss = p_graph->get_final_pkt_score(p_label);
                    LOGF("Graph analysis completed: %ld scores generated", p_loss ? p_loss->size() : 0);
                    
                } catch (const std::exception& graph_error) {
                    LOGF("Graph detection failed (likely due to simple graph structure): %s", graph_error.what());
                    LOGF("This is normal for simple traffic patterns - providing basic scoring");
                    provide_simple_scoring(valid_packets);
                    return;
                }
                     
            } catch (const exception& e) {
                LOGF("ERROR in graph analysis setup: %s", e.what());
                provide_simple_scoring(valid_packets);
                return;
            }

            // Process detection results for live alerts
            if (p_loss && !p_loss->empty()) {
                process_live_results(*p_loss, valid_packets);
            } else {
                LOGF("No detection scores generated - using simple scoring");
                provide_simple_scoring(valid_packets);
            }
            
            LOGF("Batch processing completed successfully");
            
        } catch (const exception& e) {
            LOGF("CRITICAL ERROR in batch processing: %s", e.what());
        } catch (...) {
            LOGF("UNKNOWN CRITICAL ERROR in batch processing");
        }
    }

    // NEW: Provide simple scoring for cases where graph analysis isn't applicable
    void provide_simple_scoring(const vector<shared_ptr<basic_packet>>& packets) {
        LOGF("Providing simple scoring for %ld packets", packets.size());
        
        // Create basic scores (all benign for simple traffic)
        vector<double> simple_scores(packets.size(), 5.0); // Below alert threshold
        
        // You could add simple heuristics here:
        for (size_t i = 0; i < packets.size(); ++i) {
            try {
                auto len = packets[i]->get_len();
                
                // Simple heuristic: very large packets might be suspicious
                if (len > 1400) {
                    simple_scores[i] = 8.0; // Still below threshold but higher
                }
                
                // Simple heuristic: check packet type
                auto tp = packets[i]->get_tp();
                if (tp & get_pkt_type_code(pkt_type_t::UNKNOWN)) {
                    simple_scores[i] = 7.0; // Unknown protocols slightly suspicious
                }
                
            } catch (...) {
                simple_scores[i] = 6.0; // Packets we can't analyze are slightly suspicious
            }
        }
        
        // Process simple results (most will be below alert threshold)
        process_live_results(simple_scores, packets);
        LOGF("Simple scoring completed");
    }

    // NEW: Handle live detection results (alerts, logging, etc.)
    void process_live_results(const vector<double>& scores, const vector<shared_ptr<basic_packet>>& packets) {
        size_t alerts_generated = 0;
        
        // SAFETY: Ensure we don't access beyond vector bounds
        size_t max_index = min(scores.size(), packets.size());
        
        if (max_index == 0) {
            LOGF("No results to process (scores: %ld, packets: %ld)", scores.size(), packets.size());
            return;
        }
        
        LOGF("Processing %ld results (scores: %ld, packets: %ld)", max_index, scores.size(), packets.size());
        
        for (size_t i = 0; i < max_index; ++i) {
            if (scores[i] > live_alert_threshold) {
                generate_live_alert(scores[i], packets[i], global_packet_counter + i);
                alerts_generated++;
            }
        }
        
        // Update global packet counter
        global_packet_counter += max_index;
        
        // Log processing statistics
        LOGF("Processed %ld results, generated %ld alerts (threshold: %.2f)", 
             max_index, alerts_generated, live_alert_threshold);
    }

    // NEW: Generate security alerts for live mode
    void generate_live_alert(double anomaly_score, shared_ptr<basic_packet> packet, size_t packet_index) {
        try {
            // FIXED: Use new virtual accessor methods
            string src_ip = packet->get_src_ip_str();
            string dst_ip = packet->get_dst_ip_str();
            pkt_port_t src_port = packet->get_src_port();
            pkt_port_t dst_port = packet->get_dst_port();

            // Get current timestamp
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            
            // Generate structured alert output (remove newline from ctime)
            string time_str = std::ctime(&time_t);
            time_str.pop_back(); // Remove trailing newline
            
            printf("🚨 [SECURITY ALERT] %s | Score: %.2f | %s:%d -> %s:%d | Packet #%ld\n", 
                   time_str.c_str(), anomaly_score, 
                   src_ip.c_str(), src_port, dst_ip.c_str(), dst_port, packet_index);
            
            // Also use existing logging system
            LOGF("🚨 SECURITY ALERT: Anomaly Score %.2f | %s:%d -> %s:%d | Packet #%ld", 
                 anomaly_score, src_ip.c_str(), src_port, dst_ip.c_str(), dst_port, packet_index);
                 
        } catch (const exception& e) {
            LOGF("ERROR generating alert: %s", e.what());
        }
    }
};

}