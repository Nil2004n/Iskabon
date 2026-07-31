// siem/rules/web_attack.cpp
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <regex>
#include <iomanip>
#include <chrono>
#include <sstream>
#include <ctime>

using namespace std;

// Configuration
const int WEB_ATTACK_THRESHOLD = 3;     // 3+ attempts from same IP
const int WEB_ATTACK_RESET_TIME = 60;   // Reset after 60 seconds

// Store attack attempts
map<string, int> attack_counts;                 // src_ip -> count
map<string, vector<string>> attack_logs;        // src_ip -> attack types
map<string, time_t> last_alert_time;            // src_ip -> last alert timestamp

string get_current_time() {
    auto now = chrono::system_clock::now();
    time_t now_time = chrono::system_clock::to_time_t(now);
    stringstream ss;
    ss << put_time(localtime(&now_time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

int detect_web_attack(string src_ip, string uri, string method) {
    // Check for attack patterns
    vector<string> attack_patterns = {
        "' OR '1'='1",  // SQL Injection
        "<script>",      // XSS
        "../",           // Path Traversal
        ";",             // Command Injection
        "UNION SELECT"   // SQL Injection
    };
    
    bool attack_detected = false;
    string attack_type = "Unknown";
    
    for (string pattern : attack_patterns) {
        if (uri.find(pattern) != string::npos) {
            attack_detected = true;
            attack_type = pattern;
            break;
        }
    }
    
    if (attack_detected) {
        // --- RESET LOGIC: Clear counts if 60 seconds have passed ---
        time_t now = time(nullptr);
        if (last_alert_time.find(src_ip) != last_alert_time.end() &&
            now - last_alert_time[src_ip] > WEB_ATTACK_RESET_TIME) {
            attack_counts[src_ip] = 0;
            attack_logs[src_ip].clear();
        }
        
        attack_counts[src_ip]++;
        attack_logs[src_ip].push_back(attack_type);
        
        if (attack_counts[src_ip] >= WEB_ATTACK_THRESHOLD) {
            last_alert_time[src_ip] = now;
            
            cout << "   ALERT [HIGH] Web attack detected from " << src_ip << endl;
            cout << "   Attack type: " << attack_type << endl;
            cout << "   URI: " << uri << endl;
            cout << "   Method: " << method << endl;
            cout << "   Attempts: " << attack_counts[src_ip] << endl;
            cout << "   Time: " << get_current_time() << endl;
            cout << "   ---" << endl;
            return 1;
        }
    }
    
    return 0;
}


