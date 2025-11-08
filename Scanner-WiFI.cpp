// wifi_scan.cpp   (C++17, works on Debian/Ubuntu)
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <cctype>

using namespace std;

// ------------------------------------------------------------
string trim(const string& s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == string::npos) return "";
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

// ------------------------------------------------------------
pair<string,string> splitKV(const string& line) {
    size_t pos = line.find(':');
    if (pos == string::npos) return {"",""};
    string k = trim(line.substr(0,pos));
    string v = trim(line.substr(pos+1));
    return {k,v};
}

// ------------------------------------------------------------
int freqToChannel(int freqMHz) {
    if (freqMHz >= 2412 && freqMHz <= 2484) return (freqMHz - 2407) / 5;
    if (freqMHz >= 5170 && freqMHz <= 5825) return (freqMHz - 5000) / 5;
    return 0;
}

// ------------------------------------------------------------
int main(int argc, char* argv[]) {
    string iface = (argc > 1) ? argv[1] : "wlan0";

    // ---- run iw scan ------------------------------------------------
    string cmd = "iw dev " + iface + " scan 2>/dev/null";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        cerr << "ERROR: cannot run '" << cmd << "'\n"
             << "   • Are you root? (sudo)\n"
             << "   • Does the interface exist? (iw dev)\n"
             << "   • Is 'iw' installed? (sudo apt install iw)\n";
        return 1;
    }

    // ---- parse output -----------------------------------------------
    struct AP {
        string mac, ssid, freq, signal;
        bool hasWPA3 = false, hasWPA2 = false, hasWPA = false, hasWEP = false;
    };
    vector<AP> aps;
    AP cur;

    char buf[2048];
    while (fgets(buf, sizeof(buf), pipe)) {
        string line = trim(buf);
        if (line.empty()) continue;

        if (line.rfind("BSS ",0) == 0) {               // new AP
            if (!cur.mac.empty()) aps.push_back(cur);
            cur = AP{};
            istringstream iss(line);
            string dummy; iss >> dummy >> cur.mac;     // BSS xx:xx:xx:xx:xx:xx
            continue;
        }

        auto [k,v] = splitKV(line);
        if (k.empty()) continue;

        // normalise key
        transform(k.begin(), k.end(), k.begin(), ::tolower);

        if (k == "ssid")          cur.ssid   = v;
        else if (k == "freq")     cur.freq   = v;
        else if (k == "signal")   cur.signal = v;
        else if (k.find("sae") != string::npos)   cur.hasWPA3 = true;
        else if (k.find("rsn") != string::npos)   cur.hasWPA2 = true;
        else if (k.find("wpa") != string::npos)   cur.hasWPA  = true;
        else if (k.find("wep") != string::npos)   cur.hasWEP  = true;
    }
    if (!cur.mac.empty()) aps.push_back(cur);
    pclose(pipe);

    // ---- scoring ----------------------------------------------------
    auto score = [&](const AP& a) -> int {
        if (a.hasWPA3) return 1;      // safest
        if (a.hasWPA2) return 2;
        if (a.hasWPA)  return 3;
        if (a.hasWEP)  return 4;
        return 5;                     // open
    };

    // ---- print table ------------------------------------------------
    cout << left
         << setw(30) << "SSID"
         << setw(8)  << "Ch"
         << setw(10) << "Signal"
         << setw(10) << "Enc"
         << "Score\n";
    cout << string(65,'-') << '\n';

    AP* mostVuln = nullptr;
    int  maxSc   = -1;

    for (auto& a : aps) {
        string ssid = a.ssid.empty() ? "<hidden>" : a.ssid;
        int ch = 0;
        if (!a.freq.empty()) {
            size_t pos = a.freq.find("MHz");
            if (pos != string::npos) a.freq.erase(pos);
            ch = freqToChannel(stoi(a.freq));
        }

        string enc;
        if (a.hasWPA3) enc = "WPA3";
        else if (a.hasWPA2) enc = "WPA2";
        else if (a.hasWPA)  enc = "WPA";
        else if (a.hasWEP)  enc = "WEP";
        else                enc = "Open";

        int sc = score(a);
        if (sc > maxSc) { maxSc = sc; mostVuln = &a; }

        cout << left
             << setw(30) << ssid
             << setw(8)  << (ch ? to_string(ch) : "-")
             << setw(10) << a.signal
             << setw(10) << enc
             << sc << '\n';
    }

    // ---- final advice -----------------------------------------------
    cout << "\n--- MOST VULNERABLE NETWORK ---\n";
    if (mostVuln) {
        string ssid = mostVuln->ssid.empty() ? "<hidden>" : mostVuln->ssid;
        cout << "SSID: " << ssid << "  (score " << maxSc << ")\n";
    }

    cout << R"(
SECURITY TIPS (apply to *your* network):
1. Use WPA3 (or at least WPA2-AES).
2. Strong passphrase (>=20 chars, mixed case + numbers + symbols).
3. Disable WPS.
4. Hide SSID (optional, security-by-obscurity).
5. Keep router firmware up-to-date.
6. Choose a channel with least overlap (look at the table).
)";

    return 0;
}