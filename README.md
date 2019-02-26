# Wi-Fi Sniffer

Support 2.4GHz
Based on ESP32

## Wi-Fi Sniffer Mode

### Support
* 802.11 b/g/n
* 1600 bytes hardware buffer to Rx MPDU


* 802.11 Management frame
* 802.11 Data frame, including MPDU, AMPDU, AMSDU, etc.
* 802.11 MIMO frame, for MIMO frame, the sniffer only dumps the length of the frame
### Don't support
* 802.11 Control frame
* 802.11 error frame, such as the frame with a CRC error, etc

## How to use
file 'rx_80211.py' - receive raw stream from esp32 via uart. Save 802.11 packet to *.pcap file
file 'tx_settings.py' - test functionality to send settings from PC to esp32