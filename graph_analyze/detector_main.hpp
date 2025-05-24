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
#include <mutex>

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

    // Processing mode tracking
    enum ProcessingMode { 
        DATASET_MODE,    // .data/.label files (current demo)
        PCAP_FILE_MODE,  // .pcap files (existing but unused)
        LIVE_MODE        // Live network capture (NEW)
    };
    ProcessingMode processing_mode = DATASET_MODE;

    // PAPER-ALIGNED: Live processing members
    shared_ptr<pcap_parser> p_live_parser;
    std::atomic<bool> live_processing_active{false};
    std::thread live_processing_thread;
    string live_interface_name;
    
    // PAPER-ALIGNED: Continuous traffic accumulation
    shared_ptr<vector<shared_ptr<basic_packet>>> accumulated_packets;
    mutable std::mutex accumulation_mutex;
    
    // PAPER-ALIGNED: Time-based analysis windows
    std::chrono::steady_clock::time_point last_analysis_time;
    std::chrono::steady_clock::time_point last_cleanup_time;
    
    // PAPER-ALIGNED: Configuration matching paper's parameters
    size_t micro_batch_size = 200;                    // Smaller, frequent captures
    size_t capture_timeout_ms = 1000;                 // More frequent polling
    std::chrono::seconds analysis_interval{30};       // Time-based analysis
    std::chrono::seconds flow_timeout{10};            // Paper's flow timeout
    std::chrono::seconds cleanup_interval{5};         // Paper's cleanup interval
    double live_alert_threshold = 11.0;
    size_t min_flows_for_analysis = 10;               // Require meaningful scale
    size_t min_packets_for_analysis = 50;             // Minimum accumulated packets
    
    // PAPER-ALIGNED: Packet counter for consistent indexing
    std::atomic<size_t> global_packet_counter{0};

public:
    hypervision_detector() {
        accumulated_packets = make_shared<vector<shared_ptr<basic_packet>>>();
        accumulated_packets->reserve(10000); // Pre-allocate for efficiency
        last_analysis_time = std::chrono::steady_clock::now();
        last_cleanup_time = std::chrono::steady_clock::now();
    }
    
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

        // PAPER-ALIGNED MODE 3: Continuous live network capture
        } else if (jin_main.count("live_capture") &&
                   jin_main["live_capture"].count("interface_name")) {
            
            processing_mode = LIVE_MODE;
            live_interface_name = jin_main["live_capture"]["interface_name"];
            configure_live_mode();
            start_continuous_processing();
            return; // Live mode uses continuous processing loop

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

    // ENHANCED: Configuration method with paper-aligned parameters
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

            // PAPER-ALIGNED: Live capture configuration
            if (jin.count("live_capture")) {
                const auto j_live = jin["live_capture"];
                
                if (j_live.count("micro_batch_size")) {
                    micro_batch_size = static_cast<size_t>(j_live["micro_batch_size"]);
                }
                if (j_live.count("capture_timeout_ms")) {
                    capture_timeout_ms = static_cast<size_t>(j_live["capture_timeout_ms"]);
                }
                if (j_live.count("analysis_interval_sec")) {
                    analysis_interval = std::chrono::seconds(static_cast<int>(j_live["analysis_interval_sec"]));
                }
                if (j_live.count("flow_timeout_sec")) {
                    flow_timeout = std::chrono::seconds(static_cast<int>(j_live["flow_timeout_sec"]));
                }
                if (j_live.count("cleanup_interval_sec")) {
                    cleanup_interval = std::chrono::seconds(static_cast<int>(j_live["cleanup_interval_sec"]));
                }
                if (j_live.count("min_flows_for_analysis")) {
                    min_flows_for_analysis = static_cast<size_t>(j_live["min_flows_for_analysis"]);
                }
                if (j_live.count("min_packets_for_analysis")) {
                    min_packets_for_analysis = static_cast<size_t>(j_live["min_packets_for_analysis"]);
                }
            }
            
            // Alerting configuration
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

    // PAPER-ALIGNED: Live processing control methods
    void configure_live_mode() {
        try {
            p_live_parser = make_shared<pcap_parser>(live_interface_name, true);
            if (!p_live_parser->start_live_capture()) {
                FATAL_ERROR("Failed to start live capture on " + live_interface_name);
            }
            LOGF("Live capture configured on interface: %s", live_interface_name.c_str());
            LOGF("📊 Paper-aligned parameters:");
            LOGF("   • Micro-batch size: %ld packets", micro_batch_size);
            LOGF("   • Analysis interval: %ld seconds", analysis_interval.count());
            LOGF("   • Flow timeout: %ld seconds", flow_timeout.count());
            LOGF("   • Min packets for analysis: %ld", min_packets_for_analysis);
            LOGF("   • Min flows for analysis: %ld", min_flows_for_analysis);
        } catch (const exception& e) {
            FATAL_ERROR("Live mode configuration failed: " + string(e.what()));
        }
    }

    void start_continuous_processing() {
        live_processing_active = true;
        live_processing_thread = std::thread(&hypervision_detector::continuous_processing_loop, this);
        LOGF("🚀 Continuous processing started (HyperVision paper-aligned methodology)");
        
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

    // PAPER-ALIGNED: Continuous processing main loop (FIXED - no flow constructor warnings)
    void continuous_processing_loop() {
        LOGF("🔄 Starting continuous processing loop (paper-aligned methodology)...");
        LOGF("📈 Expected behavior: Accumulate → Cleanup → Time-window analysis → Alerts");
        
        while (live_processing_active) {
            try {
                // STEP 1: Continuous micro-batch capture (paper-aligned)
                auto packets = p_live_parser->capture_packets_streaming(micro_batch_size, capture_timeout_ms);
                
                if (packets && !packets->empty()) {
                    // STEP 2: Accumulate packets continuously
                    accumulate_packets_continuously(*packets);
                }
                
                // STEP 3: Periodic flow cleanup (paper's 5-second eviction)
                if (should_cleanup_flows()) {
                    cleanup_expired_flows();
                }
                
                // STEP 4: Time-based graph analysis (paper's approach - every 30 seconds)
                if (should_perform_analysis()) {
                    perform_time_window_analysis();
                }
                
                // Brief pause to prevent excessive CPU usage
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                
            } catch (const exception& e) {
                LOGF("Continuous processing error: %s", e.what());
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
        
        LOGF("Continuous processing loop terminated");
    }

    // PAPER-ALIGNED: Continuous packet accumulation
    void accumulate_packets_continuously(const vector<shared_ptr<basic_packet>>& new_packets) {
        std::lock_guard<std::mutex> lock(accumulation_mutex);
        
        size_t valid_count = 0;
        for (const auto& pkt : new_packets) {
            if (pkt && pkt->is_valid()) {
                accumulated_packets->push_back(pkt);
                valid_count++;
            }
        }
        
        global_packet_counter += valid_count;
        
        // Log accumulation progress periodically
        static size_t last_log_count = 0;
        if (accumulated_packets->size() - last_log_count >= 1000) {
            LOGF("📦 Accumulated %ld packets (total), added %ld valid packets", 
                 accumulated_packets->size(), valid_count);
            last_log_count = accumulated_packets->size();
        }
    }
    
    // PAPER-ALIGNED: Time-based analysis (every 30 seconds, not per batch)
    bool should_perform_analysis() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_analysis_time);
        return elapsed >= analysis_interval;
    }
    
    // FIXED: Time-window analysis with fresh flow constructor (eliminates warnings)
    void perform_time_window_analysis() {
        last_analysis_time = std::chrono::steady_clock::now();
        
        std::lock_guard<std::mutex> lock(accumulation_mutex);
        
        if (accumulated_packets->empty()) {
            LOGF("⏸️  No accumulated packets for time-window analysis");
            return;
        }
        
        if (accumulated_packets->size() < min_packets_for_analysis) {
            LOGF("⏸️  Insufficient accumulated packets: %ld (need >= %ld)", 
                 accumulated_packets->size(), min_packets_for_analysis);
            return;
        }
        
        LOGF("🔍 Starting time-window analysis on %ld accumulated packets", accumulated_packets->size());
        
        try {
            // FIXED: Create fresh flow constructor for each analysis window
            // This eliminates the "Previous flow construction result detected" warning
            auto flow_constructor = make_shared<explicit_flow_constructor>(accumulated_packets);
            flow_constructor->config_via_json(jin_main["flow_construct"]);
            
            // Flow construction for accumulated packets
            flow_constructor->construct_flow(4);
            auto current_flows = flow_constructor->get_constructed_raw_flow();
            
            if (!current_flows || current_flows->size() < min_flows_for_analysis) {
                LOGF("⏸️  Insufficient flows for meaningful analysis: %ld flows (need >= %ld)", 
                     current_flows ? current_flows->size() : 0, min_flows_for_analysis);
                return;
            }
            
            LOGF("🏗️  Constructed %ld flows from accumulated packets", current_flows->size());
            
            // PAPER-ALIGNED: Graph analysis on meaningful accumulated traffic
            const auto p_edge_constructor = make_shared<edge_constructor>(current_flows);
            p_edge_constructor->config_via_json(jin_main["edge_construct"]);
            p_edge_constructor->do_construct();
            tie(p_short_edges, p_long_edges) = p_edge_constructor->get_edge();
            
            size_t total_edges = 0;
            if (p_short_edges) total_edges += p_short_edges->size();
            if (p_long_edges) total_edges += p_long_edges->size();
            
            if (total_edges < 3) {
                LOGF("⏸️  Insufficient edges for graph analysis: %ld edges (need >= 3)", total_edges);
                return;
            }
            
            LOGF("🕸️  Constructed %ld edges, performing graph detection...", total_edges);
            
            const auto p_graph = make_shared<traffic_graph>(p_short_edges, p_long_edges);
            p_graph->config_via_json(jin_main["graph_analyze"]);
            p_graph->parse_edge();
            p_graph->graph_detect();
            
            // Get scores for accumulated packets
            auto labels = make_shared<binary_label_t>(accumulated_packets->size(), false);
            auto scores = p_graph->get_final_pkt_score(labels);
            
            LOGF("✅ Graph analysis completed: %ld scores generated", scores ? scores->size() : 0);
            
            // Process results on accumulated traffic
            if (scores && !scores->empty()) {
                process_time_window_results(*scores, *accumulated_packets);
            } else {
                LOGF("⚠️  No scores generated from graph analysis");
            }
            
        } catch (const exception& e) {
            LOGF("❌ Time-window graph analysis failed: %s", e.what());
        }
    }
    
    // PAPER-ALIGNED: Flow timeout and cleanup (every 5 seconds)
    bool should_cleanup_flows() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_cleanup_time);
        return elapsed >= cleanup_interval;
    }
    
    void cleanup_expired_flows() {
        last_cleanup_time = std::chrono::steady_clock::now();
        
        std::lock_guard<std::mutex> lock(accumulation_mutex);
        
        if (accumulated_packets->empty()) {
            return;
        }
        
        // Remove packets older than flow timeout (paper's 10-second window)
        auto cutoff_time = std::chrono::steady_clock::now() - flow_timeout;
        size_t original_size = accumulated_packets->size();
        
        accumulated_packets->erase(
            std::remove_if(accumulated_packets->begin(), accumulated_packets->end(),
                [cutoff_time](const shared_ptr<basic_packet>& pkt) {
                    try {
                        auto pkt_time_sec = pkt->get_ts().tv_sec;
                        auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count();
                        
                        // Remove packets older than flow timeout
                        return (now_sec - pkt_time_sec) > 15; // 15 second cleanup window
                    } catch (...) {
                        return true; // Remove invalid packets
                    }
                }),
            accumulated_packets->end()
        );
        
        size_t cleaned_count = original_size - accumulated_packets->size();
        if (cleaned_count > 0) {
            LOGF("🧹 Cleaned up %ld expired packets, remaining: %ld", 
                 cleaned_count, accumulated_packets->size());
        }
    }
    
    // PAPER-ALIGNED: Process results from time-window analysis
    void process_time_window_results(const vector<double>& scores, 
                                   const vector<shared_ptr<basic_packet>>& packets) {
        size_t alerts_generated = 0;
        size_t high_scores = 0;
        size_t max_index = min(scores.size(), packets.size());
        
        if (max_index == 0) {
            LOGF("No results to process");
            return;
        }
        
        // Calculate statistics
        double max_score = *std::max_element(scores.begin(), scores.begin() + max_index);
        double avg_score = std::accumulate(scores.begin(), scores.begin() + max_index, 0.0) / max_index;
        
        // Count high scores (above half threshold)
        for (size_t i = 0; i < max_index; ++i) {
            if (scores[i] > live_alert_threshold / 2) {
                high_scores++;
            }
        }
        
        LOGF("📊 Time-window analysis results:");
        LOGF("   • Processed: %ld packets", max_index);
        LOGF("   • Max score: %.2f", max_score);
        LOGF("   • Avg score: %.2f", avg_score);
        LOGF("   • High scores (>%.1f): %ld", live_alert_threshold / 2, high_scores);
        
        // Generate alerts for anomalies
        for (size_t i = 0; i < max_index; ++i) {
            if (scores[i] > live_alert_threshold) {
                generate_time_window_alert(scores[i], packets[i], global_packet_counter - max_index + i);
                alerts_generated++;
            }
        }
        
        if (alerts_generated > 0) {
            LOGF("🚨 Generated %ld security alerts (threshold: %.2f)", alerts_generated, live_alert_threshold);
        } else {
            LOGF("✅ No anomalies detected in time window");
        }
    }

    // PAPER-ALIGNED: Generate alerts for time-window analysis
    void generate_time_window_alert(double anomaly_score, shared_ptr<basic_packet> packet, size_t packet_index) {
        try {
            string src_ip = packet->get_src_ip_str();
            string dst_ip = packet->get_dst_ip_str();
            pkt_port_t src_port = packet->get_src_port();
            pkt_port_t dst_port = packet->get_dst_port();

            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            string time_str = std::ctime(&time_t);
            time_str.pop_back(); // Remove trailing newline
            
            // Enhanced alert format for time-window analysis
            printf("🚨 [HYPERVISION ALERT] %s\n", time_str.c_str());
            printf("   📊 Anomaly Score: %.2f (threshold: %.2f)\n", anomaly_score, live_alert_threshold);
            printf("   🌐 Connection: %s:%d → %s:%d\n", src_ip.c_str(), src_port, dst_ip.c_str(), dst_port);
            printf("   📦 Packet Index: %ld\n", packet_index);
            printf("   🕐 Analysis: TIME-WINDOW (HyperVision)\n");
            printf("   ────────────────────────────────────────\n");
            
            LOGF("🚨 HYPERVISION SECURITY ALERT: Score=%.2f | %s:%d→%s:%d | Packet#%ld", 
                 anomaly_score, src_ip.c_str(), src_port, dst_ip.c_str(), dst_port, packet_index);
                 
        } catch (const exception& e) {
            LOGF("ERROR generating time-window alert: %s", e.what());
        }
    }
};

}