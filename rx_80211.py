import serial
import struct
import datetime
# import click


DEFAULT_TTY_ESP32 = '/dev/ttyUSB0'
# DEFAULT_TTY_ESP32_BAUDRATE = 115200
DEFAULT_TTY_ESP32_BAUDRATE = 921600

LINKTYPE_ETHERNET   = 0x1
LINKTYPE_IEEE802_11 = 0x69      # http://www.tcpdump.org/linktypes.html

ESP32_PCAP_FILE = "wifi_ALL_2.pcap"

# Global header of *.pcap file
PCAP_MAGICAL_NUMBER = 0xA1B2C3D4
PCAP_VERSION_MAJOR  = 0x2
PCAP_VERSION_MINOR  = 0x4
PCAP_THISZONE       = 0x0
PCAP_SIGFIGS        = 0x0
PCAP_SNAPLEN        = 0xFFFF
PCAP_NETWORK        = LINKTYPE_IEEE802_11



ser = serial.Serial(port=DEFAULT_TTY_ESP32,
                    baudrate=DEFAULT_TTY_ESP32_BAUDRATE,
                    timeout=None)


fin = open(ESP32_PCAP_FILE, "wb")

fin.write(struct.pack('<I', PCAP_MAGICAL_NUMBER))
fin.write(struct.pack('<H', PCAP_VERSION_MAJOR))
fin.write(struct.pack('<H', PCAP_VERSION_MINOR))
fin.write(struct.pack('<I', PCAP_THISZONE))
fin.write(struct.pack('<I', PCAP_SIGFIGS))
fin.write(struct.pack('<I', PCAP_SNAPLEN))
fin.write(struct.pack('<I', PCAP_NETWORK))

index = 0

# raw_data = ""

FRAME_DELIMITER = "<<<RfPkt>>>"
RX_WIFI_PKT = "<<<WiFi>>>"
raw_stream = ""


def check_rx_pkt(raw_pkt):
    try:
        raw_pkt.index(RX_WIFI_PKT)

    except ValueError:
        print("not wifi pkt")

    else:
        raw_pkt = raw_pkt[len(RX_WIFI_PKT):0 - len(FRAME_DELIMITER)]
        raw_pkt = struct.unpack('%dB' % len(raw_pkt), raw_pkt)
        len_raw_pkt = raw_pkt[0] | (raw_pkt[1] << 8)
        t_msec_esp32 = raw_pkt[2] | (raw_pkt[3] << 8) | (raw_pkt[4] << 16) | (raw_pkt[5] << 24)     # get timestamp
                                                                                                    # from ESP32

        if len_raw_pkt == len(raw_pkt[6:]):
            rx_802_11 = {'len': len_raw_pkt,
                         'time': t_msec_esp32,
                         'frame': raw_pkt[6:]}
            return rx_802_11


while index < 300:
    raw_frame = ser.read_until(terminator=FRAME_DELIMITER)
    print("RX from serial: ", raw_frame)

    frame_802_11 = check_rx_pkt(raw_frame)

    # pkt PCAP header
    fin.write(struct.pack('<I', frame_802_11['time'] / 1000000))
    fin.write(struct.pack('<I', frame_802_11['time']))

    fin.write(struct.pack('<I', frame_802_11['len']))
    fin.write(struct.pack('<I', frame_802_11['len']))

    fin.write(struct.pack('%dB' % frame_802_11['len'], *frame_802_11['frame']))

    print(frame_802_11)

    print("\n")
    index +=1


fin.close()
ser.close()