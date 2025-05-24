#include <gflags/gflags.h>
#include <signal.h>

#include "common.hpp"
#include "./graph_analyze/detector_main.hpp"

using namespace std;

// EXISTING: Original config flag (preserved)
DEFINE_string(config, "../configuration/lrscan/http_lrscan.json", "Configuration file location.");

// NEW: Live traffic flags (added)
DEFINE_bool(live, false, "Enable live traffic processing mode");
DEFINE_string(interface, "eth0", "Network interface for live capture");
DEFINE_bool(list_interfaces, false, "List available network interfaces and exit");

// Global detector instance for signal handling in live mode
shared_ptr<Hypervision::hypervision_detector> g_detector;

// Signal handler for graceful shutdown (live mode only)
void signal_handler(int signal) {
    if (g_detector) {
        printf("\n🛑 Received signal %d, shutting down gracefully...\n", signal);
        g_detector->stop_live_processing();
    }
    exit(0);
}

// Function to list available network interfaces
void list_network_interfaces() {
    printf("📡 Available Network Interfaces:\n");
    printf("═══════════════════════════════════════\n");
    
    try {
        // Simple interface listing - can be enhanced based on available libraries
        printf("💡 Common interfaces: eth0, eth1, wlan0, lo\n");
        printf("💡 Use 'ip link show' or 'ifconfig' to see all interfaces\n");
        printf("💡 Usage: ./HyperVision --live --interface=<interface_name>\n");
        printf("   Example: ./HyperVision --live --interface=eth0\n");
        
    } catch (const exception& e) {
        printf("❌ Error: %s\n", e.what());
    }
}

int main(int argc, char * argv[]) {
    __START_FTIMMER__

    google::ParseCommandLineFlags(&argc, &argv, true);

    // NEW: Handle special modes
    if (FLAGS_list_interfaces) {
        list_network_interfaces();
        return 0;
    }

    json config_j;
    try {
        ifstream fin(FLAGS_config, ios::in);
        fin >> config_j;
    } catch (const exception & e) {
        FATAL_ERROR(e.what());
    }

    // EXISTING: Create detector (preserved)
    auto hv1 = make_shared<Hypervision::hypervision_detector>();
    
    // NEW: Live mode support
    if (FLAGS_live) {
        // Set global reference for signal handling
        g_detector = hv1;
        
        // Setup signal handlers for graceful shutdown
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        
        // Override interface in configuration if live mode
        config_j["live_capture"]["interface_name"] = FLAGS_interface;
        
        printf("🚀 HyperVision Live Traffic Analysis\n");
        printf("═══════════════════════════════════════\n");
        printf("📡 Interface: %s\n", FLAGS_interface.c_str());
        printf("📝 Config: %s\n", FLAGS_config.c_str());
        printf("💡 Press Ctrl+C to stop gracefully\n");
        printf("═══════════════════════════════════════\n\n");
    } else {
        // EXISTING: Original mode message (preserved)
        printf("🗂️  HyperVision Analysis\n");
        printf("📝 Config: %s\n", FLAGS_config.c_str());
        printf("═══════════════════════════════════════\n\n");
    }

    // EXISTING: Configure and start (preserved)
    hv1->config_via_json(config_j);
    hv1->start();
 
    __STOP_FTIMER__
    __PRINTF_EXE_TIME__

    return 0;
}