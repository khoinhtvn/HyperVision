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
#include <queue>
#include <unordered_set>
#include <boost/functional/hash.hpp>

// COMPILATION FIX: Add missing system includes
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstring>

namespace Hypervision
{

// COMPILATION FIX: Add missing function for protocol name conversion
inline const char* get_protocol_name_from_code(uint8_t proto_code) {
    switch(proto_code) {
        case 1: return "ICMP";
        case 6: return "TCP"; 
        case 17: return "UDP";
        case 58: return "ICMPv6";
        default: return "UNKNOWN";
    }
}

// PAPER-ALIGNED: Flow hash table types (from explicit_constructor.cpp)
using flow_hash_4_t = tuple5_conn4;
using flow_H_table_entry_4_t = shared_ptr<tuple5_flow4>;
using flow_H_table_4_t = unordered_map<flow_hash_4_t, flow_H_table_entry_4_t, boost::hash<flow_hash_4_t>>;

using flow_hash_6_t = tuple5_conn6;
using flow_H_table_entry_6_t = shared_ptr<tuple5_flow6>;
using flow_H_table_6_t = unordered_map<flow_hash_6_t, flow_H_table_entry_6_t, boost::hash<flow_hash_6_t>>;

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
    std::thread flow_collection_thread;
    string live_interface_name;
    
    // PAPER-ALIGNED: Persistent flow hash tables (matches Algorithm 1)
    flow_H_table_4_t persistent_flow_table_4;
    flow_H_table_6_t persistent_flow_table_6;
    mutable std::mutex flow_tables_mutex;
    
    // PAPER-ALIGNED: Packet processing queue
    std::queue<shared_ptr<basic_packet>> packet_processing_queue;
    mutable std::mutex packet_queue_mutex;
    std::condition_variable packet_queue_condition;
    
    // PAPER-ALIGNED: Completed flow batches for analysis
    std::queue<vector<shared_ptr<basic_flow>>> completed_flow_batches;
    mutable std::mutex batch_queue_mutex;
    std::condition_variable batch_queue_condition;
    
    // PAPER-ALIGNED: Timing parameters (matches paper's Algorithm 1)
    double PKT_TIMEOUT = 10.0;                    // Paper's flow timeout
    double JUDGE_INTERVAL = 5.0;                  // Paper's collection interval
    double EVICT_FLOW_TIME_OUT = 5.0;            // Paper's cleanup interval
    std::chrono::steady_clock::time_point TIME_NOW;
    std::chrono::steady_clock::time_point last_judge_time;
    std::chrono::steady_clock::time_point system_start_time;
    
    // Configuration parameters
    size_t max_packet_queue_size = 50000;
    size_t max_batch_queue_size = 100;
    size_t packet_capture_batch_size = 1000;
    size_t capture_timeout_ms = 500;
    double live_alert_threshold = 11.0;
    
    // Performance counters
    std::atomic<size_t> total_packets_processed{0};
    std::atomic<size_t> total_flows_created{0};
    std::atomic<size_t> total_batches_analyzed{0};
    std::atomic<size_t> total_alerts_generated{0};
    std::atomic<size_t> packets_dropped_queue_full{0};

public:
    hypervision_detector() {
        auto now = std::chrono::steady_clock::now();
        TIME_NOW = now;
        last_judge_time = now;
        system_start_time = now;
    }
    
    ~hypervision_detector() {
        stop_live_processing();
    }

    // ENHANCED: Main processing method (supports all modes)
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

        // PAPER-ALIGNED MODE 3: Live micro-batch processing
        } else if (jin_main.count("live_capture") &&
                   jin_main["live_capture"].count("interface_name")) {
            
            processing_mode = LIVE_MODE;
            live_interface_name = jin_main["live_capture"]["interface_name"];
            configure_live_mode();
            start_paper_aligned_live_processing();
            return; // Live mode uses persistent processing loop

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
                
                if (j_live.count("pkt_timeout")) {
                    PKT_TIMEOUT = static_cast<double>(j_live["pkt_timeout"]);
                }
                if (j_live.count("judge_interval")) {
                    JUDGE_INTERVAL = static_cast<double>(j_live["judge_interval"]);
                }
                if (j_live.count("evict_flow_time_out")) {
                    EVICT_FLOW_TIME_OUT = static_cast<double>(j_live["evict_flow_time_out"]);
                }
                if (j_live.count("max_packet_queue_size")) {
                    max_packet_queue_size = static_cast<size_t>(j_live["max_packet_queue_size"]);
                }
                if (j_live.count("packet_capture_batch_size")) {
                    packet_capture_batch_size = static_cast<size_t>(j_live["packet_capture_batch_size"]);
                }
                if (j_live.count("capture_timeout_ms")) {
                    capture_timeout_ms = static_cast<size_t>(j_live["capture_timeout_ms"]);
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
            // FIXED: Use the exact constructor signature from your pcap_parser.hpp
            p_live_parser = make_shared<pcap_parser>(live_interface_name, true);
            if (!p_live_parser->start_live_capture()) {
                FATAL_ERROR("Failed to start live capture on " + live_interface_name);
            }
            
            LOGF("🚀 HyperVision Paper-Aligned Live Processing Configured");
            LOGF("📡 Interface: %s", live_interface_name.c_str());
            LOGF("⏱️  PKT_TIMEOUT: %.1fs (flow completion)", PKT_TIMEOUT);
            LOGF("🔄 JUDGE_INTERVAL: %.1fs (batch collection)", JUDGE_INTERVAL);
            LOGF("🧹 EVICT_TIMEOUT: %.1fs (cleanup interval)", EVICT_FLOW_TIME_OUT);
            LOGF("📦 Packet queue size: %ld", max_packet_queue_size);
            LOGF("🎯 Alert threshold: %.2f", live_alert_threshold);
            LOGF("📊 Architecture: Persistent Flow Tables + Micro-Batch Analysis");
            
        } catch (const exception& e) {
            FATAL_ERROR("Live mode configuration failed: " + string(e.what()));
        }
    }

    void start_paper_aligned_live_processing() {
        live_processing_active = true;
        
        // Start three processing threads (paper-aligned pipeline)
        live_processing_thread = std::thread(&hypervision_detector::packet_capture_loop, this);
        flow_collection_thread = std::thread(&hypervision_detector::flow_processing_loop, this);
        
        LOGF("🚀 Paper-aligned live processing started with 3-thread architecture:");
        LOGF("   Thread 1: Packet capture + Flow construction");
        LOGF("   Thread 2: Flow collection + Batch creation"); 
        LOGF("   Thread 3: Graph analysis + Detection (main thread)");
        
        // Main thread handles batch analysis
        batch_analysis_loop();
        
        // Wait for threads to complete
        if (live_processing_thread.joinable()) {
            live_processing_thread.join();
        }
        if (flow_collection_thread.joinable()) {
            flow_collection_thread.join();
        }
    }

    void stop_live_processing() {
        if (live_processing_active) {
            live_processing_active = false;
            
            // Stop capture
            if (p_live_parser) {
                p_live_parser->stop_live_capture();
            }
            
            // Wake up waiting threads
            packet_queue_condition.notify_all();
            batch_queue_condition.notify_all();
            
            // Wait for threads
            if (live_processing_thread.joinable()) {
                live_processing_thread.join();
            }
            if (flow_collection_thread.joinable()) {
                flow_collection_thread.join();
            }
            
            LOGF("Paper-aligned live processing stopped");
            print_final_statistics();
        }
    }

private:
    // EXISTING: Batch processing pipeline (unchanged)
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

    // PAPER-ALIGNED: Thread 1 - Packet capture and flow construction
    void packet_capture_loop() {
        LOGF("🔄 Starting packet capture + flow construction loop");
        
        while (live_processing_active) {
            try {
                // Capture packets in batches
                auto new_packets = p_live_parser->capture_packets_streaming(
                    packet_capture_batch_size, capture_timeout_ms);
                
                if (new_packets && !new_packets->empty()) {
                    // Process packets into persistent flow tables
                    process_packets_into_flows(*new_packets);
                }
                
                // Brief pause to prevent excessive CPU usage
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                
            } catch (const exception& e) {
                LOGF("Packet capture error: %s", e.what());
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
        
        LOGF("Packet capture loop terminated");
    }

    // PAPER-ALIGNED: Thread 2 - Flow collection and batch creation
    void flow_processing_loop() {
        LOGF("🔄 Starting flow collection + batch creation loop");
        
        while (live_processing_active) {
            try {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - last_judge_time).count() / 1000.0;
                
                if (elapsed >= JUDGE_INTERVAL) {
                    // PAPER-ALIGNED: Collect completed flows (Algorithm 1)
                    collect_completed_flows();
                    last_judge_time = now;
                }
                
                // Sleep until next judge interval
                auto sleep_time = std::chrono::milliseconds(
                    static_cast<long>(JUDGE_INTERVAL * 1000 / 4)); // Check 4x per interval
                std::this_thread::sleep_for(sleep_time);
                
            } catch (const exception& e) {
                LOGF("Flow collection error: %s", e.what());
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
        
        LOGF("Flow collection loop terminated");
    }

    // PAPER-ALIGNED: Thread 3 - Batch analysis (main thread)
    void batch_analysis_loop() {
        LOGF("🔄 Starting batch analysis loop (main thread)");
        
        while (live_processing_active) {
            try {
                // Wait for completed flow batch
                std::unique_lock<std::mutex> lock(batch_queue_mutex);
                batch_queue_condition.wait(lock, [this] {
                    return !completed_flow_batches.empty() || !live_processing_active;
                });
                
                if (!live_processing_active) {
                    break;
                }
                
                // Get batch for analysis
                auto flow_batch = completed_flow_batches.front();
                completed_flow_batches.pop();
                lock.unlock();
                
                if (!flow_batch.empty()) {
                    // PAPER-ALIGNED: Complete pipeline analysis on batch
                    analyze_flow_batch(flow_batch);
                }
                
            } catch (const exception& e) {
                LOGF("Batch analysis error: %s", e.what());
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
        
        LOGF("Batch analysis loop terminated");
    }

    // PAPER-ALIGNED: Process packets into persistent flow tables (matches explicit_flow_constructor logic)
    void process_packets_into_flows(const vector<shared_ptr<basic_packet>>& packets) {
        std::lock_guard<std::mutex> lock(flow_tables_mutex);
        TIME_NOW = std::chrono::steady_clock::now();
        
        size_t valid_packets = 0;
        for (const auto& p_packet : packets) {
            if (!p_packet || typeid(*p_packet) == typeid(basic_packet_bad)) {
                continue;
            }
            
            const auto packet_time = GET_DOUBLE_TS(p_packet->ts);
            
            if (typeid(*p_packet) == typeid(basic_packet4)) {
                process_ipv4_packet(dynamic_pointer_cast<basic_packet4>(p_packet), packet_time);
            } else if (typeid(*p_packet) == typeid(basic_packet6)) {
                process_ipv6_packet(dynamic_pointer_cast<basic_packet6>(p_packet), packet_time);
            }
            
            valid_packets++;
        }
        
        total_packets_processed += valid_packets;
        
        // Log progress periodically
        static size_t last_log_total = 0;
        if (total_packets_processed - last_log_total >= 5000) {
            LOGF("📦 Processed %ld packets, Active flows: [IPv4: %ld, IPv6: %ld]", 
                 total_packets_processed.load(), 
                 persistent_flow_table_4.size(), 
                 persistent_flow_table_6.size());
            last_log_total = total_packets_processed;
        }
    }

    // PAPER-ALIGNED: IPv4 packet processing (matches explicit_flow_constructor)
    void process_ipv4_packet(shared_ptr<basic_packet4> packet, double packet_time) {
        const auto stack_code = convert_packet2stack_code(packet->tp);
        const auto flow_id = tuple4_extend(packet->flow_id, stack_code);
        
        if (persistent_flow_table_4.find(flow_id) == persistent_flow_table_4.end()) {
            // Create new flow
            const auto new_flow = make_shared<tuple5_flow4>(flow_id);
            new_flow->emplace_packet(packet, total_packets_processed);
            persistent_flow_table_4.insert({flow_id, new_flow});
            total_flows_created++;
        } else {
            // Add to existing flow
            persistent_flow_table_4[flow_id]->emplace_packet(packet, total_packets_processed);
        }
    }

    // PAPER-ALIGNED: IPv6 packet processing (matches explicit_flow_constructor)
    void process_ipv6_packet(shared_ptr<basic_packet6> packet, double packet_time) {
        const auto stack_code = convert_packet2stack_code(packet->tp);
        const auto flow_id = tuple4_extend(packet->flow_id, stack_code);
        
        if (persistent_flow_table_6.find(flow_id) == persistent_flow_table_6.end()) {
            // Create new flow
            const auto new_flow = make_shared<tuple5_flow6>(flow_id);
            new_flow->emplace_packet(packet, total_packets_processed);
            persistent_flow_table_6.insert({flow_id, new_flow});
            total_flows_created++;
        } else {
            // Add to existing flow
            persistent_flow_table_6[flow_id]->emplace_packet(packet, total_packets_processed);
        }
    }

    // PAPER-ALIGNED: Collect completed flows (Algorithm 1 - JUDGE_INTERVAL logic)
    void collect_completed_flows() {
        std::lock_guard<std::mutex> lock(flow_tables_mutex);
        auto current_time = std::chrono::steady_clock::now();
        auto current_time_double = std::chrono::duration_cast<std::chrono::microseconds>(
            current_time.time_since_epoch()).count() / 1e6;
        
        vector<shared_ptr<basic_flow>> completed_flows;
        
        // Collect completed IPv4 flows
        unordered_set<flow_hash_4_t, boost::hash<flow_hash_4_t>> completed_flow_ids_4;
        for (const auto& flow_pair : persistent_flow_table_4) {
            const auto& flow = flow_pair.second;
            if ((current_time_double - flow->get_end_time() - PKT_TIMEOUT) > EPS) {
                completed_flows.push_back(flow);
                completed_flow_ids_4.insert(flow_pair.first);
            }
        }
        
        // Remove completed IPv4 flows
        for (const auto& flow_id : completed_flow_ids_4) {
            persistent_flow_table_4.erase(flow_id);
        }
        
        // Collect completed IPv6 flows
        unordered_set<flow_hash_6_t, boost::hash<flow_hash_6_t>> completed_flow_ids_6;
        for (const auto& flow_pair : persistent_flow_table_6) {
            const auto& flow = flow_pair.second;
            if ((current_time_double - flow->get_end_time() - PKT_TIMEOUT) > EPS) {
                completed_flows.push_back(flow);
                completed_flow_ids_6.insert(flow_pair.first);
            }
        }
        
        // Remove completed IPv6 flows
        for (const auto& flow_id : completed_flow_ids_6) {
            persistent_flow_table_6.erase(flow_id);
        }
        
        if (!completed_flows.empty()) {
            // Add batch to analysis queue
            std::lock_guard<std::mutex> batch_lock(batch_queue_mutex);
            if (completed_flow_batches.size() < max_batch_queue_size) {
                completed_flow_batches.push(completed_flows);
                batch_queue_condition.notify_one();
                
                LOGF("📊 Collected %ld completed flows for batch analysis #%ld", 
                     completed_flows.size(), total_batches_analyzed.load() + 1);
            } else {
                LOGF("⚠️  Batch queue full, dropping %ld flows", completed_flows.size());
            }
        }
    }

    // PAPER-ALIGNED: Complete batch analysis (full HyperVision pipeline)
    void analyze_flow_batch(const vector<shared_ptr<basic_flow>>& flow_batch) {
        if (flow_batch.empty()) {
            return;
        }
        
        total_batches_analyzed++;
        auto batch_start_time = std::chrono::steady_clock::now();
        
        try {
            LOGF("🔍 Starting batch analysis #%ld (%ld flows)", 
                 total_batches_analyzed.load(), flow_batch.size());
            
            // Convert to shared_ptr for compatibility
            auto batch_flows = make_shared<vector<shared_ptr<basic_flow>>>(flow_batch);
            
            // PAPER-ALIGNED: Edge construction
            const auto p_edge_constructor = make_shared<edge_constructor>(batch_flows);
            p_edge_constructor->config_via_json(jin_main["edge_construct"]);
            p_edge_constructor->do_construct();
            tie(p_short_edges, p_long_edges) = p_edge_constructor->get_edge();
            
            size_t total_edges = 0;
            if (p_short_edges) total_edges += p_short_edges->size();
            if (p_long_edges) total_edges += p_long_edges->size();
            
            if (total_edges < 3) {
                LOGF("⏸️  Insufficient edges for analysis: %ld edges", total_edges);
                return;
            }
            
            LOGF("🕸️  Constructed %ld edges (%ld short, %ld long)", 
                 total_edges, 
                 p_short_edges ? p_short_edges->size() : 0,
                 p_long_edges ? p_long_edges->size() : 0);
            
            // PAPER-ALIGNED: Graph analysis
            const auto p_graph = make_shared<traffic_graph>(p_short_edges, p_long_edges);
            p_graph->config_via_json(jin_main["graph_analyze"]);
            p_graph->parse_edge();
            p_graph->graph_detect();
            
            // Get detection scores (no ground truth in live mode)
            auto dummy_labels = make_shared<binary_label_t>(flow_batch.size(), false);
            auto scores = p_graph->get_final_pkt_score(dummy_labels);
            
            auto batch_end_time = std::chrono::steady_clock::now();
            auto analysis_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                batch_end_time - batch_start_time);
            
            LOGF("✅ Batch analysis #%ld completed in %ldms", 
                 total_batches_analyzed.load(), analysis_duration.count());
            
            // Process results
            if (scores && !scores->empty()) {
                process_batch_results(*scores, flow_batch);
            }
            
        } catch (const exception& e) {
            LOGF("❌ Batch analysis #%ld failed: %s", 
                 total_batches_analyzed.load(), e.what());
        }
    }

    // PAPER-ALIGNED: Process batch results and generate alerts
    void process_batch_results(const vector<double>& scores, 
                             const vector<shared_ptr<basic_flow>>& flows) {
        size_t alerts_generated = 0;
        size_t high_scores = 0;
        size_t max_index = min(scores.size(), flows.size());
        
        if (max_index == 0) return;
        
        // Calculate statistics
        double max_score = *std::max_element(scores.begin(), scores.begin() + max_index);
        double avg_score = std::accumulate(scores.begin(), scores.begin() + max_index, 0.0) / max_index;
        
        // Count suspicious flows
        for (size_t i = 0; i < max_index; ++i) {
            if (scores[i] > live_alert_threshold / 2) {
                high_scores++;
            }
        }
        
        auto runtime = std::chrono::duration_cast<std::chrono::minutes>(
            std::chrono::steady_clock::now() - system_start_time);
        
        LOGF("📊 Batch #%ld Analysis Results [Runtime: %ld min]:", 
             total_batches_analyzed.load(), runtime.count());
        LOGF("   • Flows analyzed: %ld", max_index);
        LOGF("   • Max anomaly score: %.2f", max_score);
        LOGF("   • Avg anomaly score: %.2f", avg_score);
        LOGF("   • Suspicious flows (>%.1f): %ld", live_alert_threshold / 2, high_scores);
        LOGF("   • Active flows: [IPv4: %ld, IPv6: %ld]", 
             persistent_flow_table_4.size(), persistent_flow_table_6.size());
        
        // Generate alerts
        for (size_t i = 0; i < max_index; ++i) {
            if (scores[i] > live_alert_threshold) {
                generate_security_alert(scores[i], flows[i], total_batches_analyzed);
                alerts_generated++;
            }
        }
        
        total_alerts_generated += alerts_generated;
        
        if (alerts_generated > 0) {
            LOGF("🚨 SECURITY ALERTS: %ld new alerts (total: %ld)", 
                 alerts_generated, total_alerts_generated.load());
        } else {
            LOGF("✅ No anomalies detected in batch #%ld", total_batches_analyzed.load());
        }
    }

    // PAPER-ALIGNED: Generate security alert for detected anomaly
    void generate_security_alert(double anomaly_score, shared_ptr<basic_flow> flow, 
                               size_t batch_number) {
        try {
            // Extract flow information
            string src_ip, dst_ip;
            pkt_port_t src_port = 0, dst_port = 0;
            string protocol = "UNKNOWN";
            
            // Handle IPv4 flows
            if (auto flow4 = dynamic_pointer_cast<tuple5_flow4>(flow)) {
                auto flow_id = flow4->flow_id;
                
                // COMPILATION FIX: Proper IPv4 address conversion
                struct in_addr addr_src, addr_dst;
                addr_src.s_addr = htonl(get<0>(flow_id));
                addr_dst.s_addr = htonl(get<1>(flow_id));
                src_ip = string(inet_ntoa(addr_src));
                dst_ip = string(inet_ntoa(addr_dst));
                
                src_port = get<2>(flow_id);
                dst_port = get<3>(flow_id);
                
                // COMPILATION FIX: Use our helper function instead of missing one
                protocol = get_protocol_name_from_code(get<4>(flow_id));
            }
            // Handle IPv6 flows
            else if (auto flow6 = dynamic_pointer_cast<tuple5_flow6>(flow)) {
                auto flow_id = flow6->flow_id;
                // IPv6 address conversion (simplified for now)
                src_ip = "IPv6_SRC";
                dst_ip = "IPv6_DST"; 
                src_port = get<2>(flow_id);
                dst_port = get<3>(flow_id);
                
                // COMPILATION FIX: Use our helper function
                protocol = get_protocol_name_from_code(get<4>(flow_id));
            }
            
            // Get flow statistics
            size_t packet_count = 0;
            double flow_duration = 0.0;
            if (flow->get_p_packet_p_seq()) {
                packet_count = flow->get_p_packet_p_seq()->size();
                flow_duration = flow->get_fct();
            }
            
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            string time_str = std::ctime(&time_t);
            time_str.pop_back();
            
            auto runtime = std::chrono::duration_cast<std::chrono::minutes>(
                std::chrono::steady_clock::now() - system_start_time);
            
            // Generate comprehensive alert
            printf("🚨 ═══════════════════════════════════════════════════════════════\n");
            printf("   HYPERVISION ENCRYPTED MALICIOUS TRAFFIC ALERT\n");
            printf("   Paper-Aligned Live Detection System\n");
            printf("═══════════════════════════════════════════════════════════════\n");
            printf("🕐 Timestamp: %s\n", time_str.c_str());
            printf("🎯 Anomaly Score: %.2f (threshold: %.2f)\n", anomaly_score, live_alert_threshold);
            printf("🌐 Flow: %s:%d → %s:%d (%s)\n", 
                   src_ip.c_str(), src_port, dst_ip.c_str(), dst_port, protocol.c_str());
            printf("📊 Flow Stats: %ld packets, %.2fs duration\n", packet_count, flow_duration);
            printf("📈 Batch: #%ld (Total processed: %ld packets)\n", 
                   batch_number, total_packets_processed.load());
            printf("⏱️  System Runtime: %ld minutes\n", runtime.count());
            printf("🔄 Detection Mode: PAPER-ALIGNED MICRO-BATCH\n");
            printf("📊 Performance: %ld batches analyzed, %ld total alerts\n", 
                   total_batches_analyzed.load(), total_alerts_generated.load() + 1);
            printf("═══════════════════════════════════════════════════════════════\n");
            
        } catch (const exception& e) {
            LOGF("ERROR generating security alert: %s", e.what());
        }
    }

    void print_final_statistics() {
        auto runtime = std::chrono::duration_cast<std::chrono::minutes>(
            std::chrono::steady_clock::now() - system_start_time);
            
        LOGF("📈 HYPERVISION PAPER-ALIGNED FINAL STATISTICS:");
        LOGF("   • Total runtime: %ld minutes", runtime.count());
        LOGF("   • Total packets processed: %ld", total_packets_processed.load());
        LOGF("   • Total flows created: %ld", total_flows_created.load());
        LOGF("   • Total batches analyzed: %ld", total_batches_analyzed.load());
        LOGF("   • Total security alerts: %ld", total_alerts_generated.load());
        LOGF("   • Packets dropped (queue full): %ld", packets_dropped_queue_full.load());
        LOGF("   • Average batch interval: %.1f minutes", 
             total_batches_analyzed > 0 ? (runtime.count() / (double)total_batches_analyzed) : 0.0);
        LOGF("   • Detection rate: %.2f alerts/hour", 
             runtime.count() > 0 ? (total_alerts_generated.load() * 60.0 / runtime.count()) : 0.0);
        LOGF("   • Flow processing rate: %.1f flows/min", 
             runtime.count() > 0 ? (total_flows_created.load() / (double)runtime.count()) : 0.0);
    }
};

}