# WiFi Security Scanner (`wifi_scan`)

> **Passively scan nearby Wi-Fi networks and identify the most vulnerable one** – perfect for testing **your own network** security.

This tool uses the Linux `iw` command to list all visible access points, extracts SSID, channel, signal strength, and encryption type (Open/WEP/WPA/WPA2/WPA3), then assigns a **vulnerability score** (1 = safest, 5 = open/unprotected).

**Ethical use only** – scan only networks you own or have explicit permission to test.

---

## Features

- Zero packet injection – **100% passive**
- Detects WPA3, WPA2, WPA, WEP, Open
- Converts frequency → channel number
- Clean table output with signal strength
- Highlights the **most vulnerable network**
- Built-in security improvement checklist

---

## Screenshot
