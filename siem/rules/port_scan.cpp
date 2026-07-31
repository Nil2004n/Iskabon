// siem/rules/port_scan.cpp
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <set>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <ctime>

using namespace std;

// Configuration
const int PORT_SCAN_THRESHOLD = 10;      // 10+ unique ports
const int PORT_SCAN_WINDOW = 60;         // in seconds

// Store port scan data
map<string, set<int>> scanned_ports;           // src_ip -> set of ports
map<string, vector<time_t>> scan_timestamps;   // src_ip -> timestamps

string get_current_time_port() {
    auto now = chrono::system_clock::now();
    time_t now_time = chrono::system_clock::to_time_t(now);
    stringstream ss;
    ss << put_time(localtime(&now_time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

int detect_port_scan(string src_ip, int dst_port, time_t timestamp) {
    // Add this scan
    scanned_ports[src_ip].insert(dst_port);
    scan_timestamps[src_ip].push_back(timestamp);
    
    // --- PRUNE OLD DATA (fix for #5) ---
    time_t cutoff = timestamp - PORT_SCAN_WINDOW;
    vector<time_t> recent_timestamps;
    for (time_t t : scan_timestamps[src_ip]) {
        if (t >= cutoff) {
            recent_timestamps.push_back(t);
        }
    }
    scan_timestamps[src_ip] = recent_timestamps;
    
    // Count unique ports scanned in the window
    int unique_ports = scanned_ports[src_ip].size();
    
    if (unique_ports >= PORT_SCAN_THRESHOLD) {
        cout << "   ALERT [HIGH] Port scan detected from " << src_ip << endl;
        cout << "   Unique ports scanned: " << unique_ports << " in last " << PORT_SCAN_WINDOW << " seconds" << endl;
        cout << "   Time: " << get_current_time_port() << endl;
        cout << "   ---" << endl;
        return 1;
    }
    return 0;
}
