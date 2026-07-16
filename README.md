# WiFi Scanner

A lightweight Flask web application that displays all nearby WiFi networks in a real-time, auto-refreshing dashboard. Perfect for monitoring network availability and signal strength from your browser.

## Features

- **Real-time WiFi Network Scanning** - Automatically detects and displays nearby WiFi networks
- **Signal Strength Visualization** - Shows signal strength indicators for each network
- **Security Information** - Displays encryption type (Open, WEP, WPA, WPA2, WPA3)
- **Network Details** - Shows BSSID, channel, and signal strength (RSSI/dBm)
- **Auto-Refresh Dashboard** - Network list updates every few seconds
- **Cross-Platform Support** - Works on Windows, macOS, and Linux
- **Passive Scanning** - No interference with networks; just reads public information

## How It Works

**Backend (Flask Server)**:
- Provides two main routes:
  - `GET /` - Serves the dashboard webpage
  - `GET /scan` - Queries the operating system for visible networks and returns JSON data

**Frontend (Web Dashboard)**:
- JavaScript periodically calls `/scan` to fetch network data
- Parses the JSON response and updates the network list
- Displays signal strength bars and network details in real-time

## What This App Does

✅ **Can Do**:
- List all visible WiFi networks (same list as your OS shows in the taskbar)
- Display signal strength and security information
- Provide a web interface for easy monitoring
- Work completely passively without connecting to networks

❌ **Cannot Do**:
- Connect to WiFi networks
- Capture network traffic
- Interfere with any networks
- Transmit or receive data from networks

## Requirements

- Python 3.7 or higher
- Flask 3.0+

## Installation

1. Clone or download this repository:
```bash
git clone https://github.com/yourusername/wifi-scanner.git
cd wifi-scanner
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the Flask server:
```bash
python app.py
```

2. Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

3. The dashboard will automatically scan and display nearby WiFi networks, refreshing every few seconds.

## Platform-Specific Notes

### macOS
- Uses the built-in `airport` command
- **Note**: Newer macOS versions restrict access to WiFi information and may require Location Services permission for Terminal
- If no networks appear, check System Preferences → Security & Privacy → Location Services

### Windows
- Uses `netsh wlan show networks mode=bssid` command
- Requires administrator privileges on some systems
- Works with Windows 7 and later

### Linux
- Uses `nmcli` (NetworkManager command)
- Install NetworkManager if not already installed:
  ```bash
  sudo apt-get install network-manager  # Ubuntu/Debian
  sudo yum install NetworkManager        # RedHat/CentOS
  ```

## Network Information Displayed

| Field | Description |
|-------|-------------|
| SSID | Network name (empty/hidden for hidden networks) |
| BSSID | MAC address of the access point |
| Signal | Signal strength as percentage (0-100%) |
| RSSI | Signal strength in dBm (typically -30 to -90) |
| Channel | WiFi channel number |
| Security | Encryption type (Open, WEP, WPA, WPA2, WPA3) |

## Troubleshooting

**No networks appear on the dashboard:**
- Check OS permissions (especially on macOS)
- Ensure WiFi is enabled on your computer
- Try running the app with administrator/sudo privileges

**Permission denied errors:**
- On Windows: Run Command Prompt/PowerShell as Administrator
- On Linux: Run with `sudo`
- On macOS: Grant Terminal Location Services permission

**Flask server won't start:**
- Ensure Flask is installed: `pip install flask`
- Check if port 5000 is already in use
- Try a different port: `python app.py --port=5001`

## Privacy & Security

This application is completely **passive** and **local**:
- It only reads publicly available network information
- All processing happens locally on your computer
- No data is sent to external servers
- No network traffic is captured or modified

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Feel free to:
- Report bugs and issues
- Suggest new features
- Submit pull requests with improvements

## Author

Created as a simple utility for WiFi network monitoring.

---

**Questions or Issues?** Please open an issue on GitHub or check the troubleshooting section above.
