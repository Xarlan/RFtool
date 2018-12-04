# Wi-Fi Sniffer

Support 2.4GHz
Based on ESP32

## Wi-Fi Sniffer Mode
### Support
* 802.11 Management frame
* 802.11 Data frame, including MPDU, AMPDU, AMSDU, etc.
* 802.11 MIMO frame, for MIMO frame, the sniffer only dumps the length of the frame
### Don't support
* 802.11 Control frame
* 802.11 error frame, such as the frame with a CRC error, etc

## How to use
Run
$python3.5 rftool.py
The result will be store in esp32.pcap file.
Open this file in wireshark