import serial
import struct
import datetime
# import click


DEFAULT_TTY_ESP32 = '/dev/ttyUSB0'
DEFAULT_TTY_ESP32_BAUDRATE = 115200

LINKTYPE_ETHERNET   = 0x1
LINKTYPE_IEEE802_11 = 0x69      # http://www.tcpdump.org/linktypes.html

ESP32_PCAP_FILE = "wifi_mgmt_02.pcap"

# Global header of *.pcap file
PCAP_MAGICAL_NUMBER = 0xA1B2C3D4
PCAP_VERSION_MAJOR  = 0x2
PCAP_VERSION_MINOR  = 0x4
PCAP_THISZONE       = 0x0
PCAP_SIGFIGS        = 0x0
PCAP_SNAPLEN        = 0xFFFF
PCAP_NETWORK        = LINKTYPE_IEEE802_11


ser = serial.Serial('/dev/ttyUSB0', baudrate=115200)
# ser = serial.Serial('/dev/ttyUSB0', baudrate=921600)
# # print ser.read(10)
# # ser.write(b'helloqwert\n')
#


fin = open(ESP32_PCAP_FILE, "wb")

fin.write(struct.pack('<I', PCAP_MAGICAL_NUMBER))
fin.write(struct.pack('<H', PCAP_VERSION_MAJOR))
fin.write(struct.pack('<H', PCAP_VERSION_MINOR))
fin.write(struct.pack('<I', PCAP_THISZONE))
fin.write(struct.pack('<I', PCAP_SIGFIGS))
fin.write(struct.pack('<I', PCAP_SNAPLEN))
fin.write(struct.pack('<I', PCAP_NETWORK))

index = 0

raw_data = ""

while index < 7000:
# while True:
    # # pkt header
    # fin.write(struct.pack('<I', datetime.datetime.now().second))
    # fin.write(struct.pack('<I', datetime.datetime.now().microsecond))
    #
    # # raw_len_pkt = struct.unpack('3B', ser.readline())
    # # len_pkt = (raw_len_pkt[1] << 8) | raw_len_pkt[0]
    #
    # # print("len pkt = {}".format(len_pkt))
    # # print("len pkt = {}".format(struct.unpack('3B', len_pkt)))
    #
    # # fin.write(struct.pack('<I', len_pkt))
    # # fin.write(struct.pack('<I', len_pkt))
    #
    # # raw_data = ser.read(len_pkt)
    # raw_data = ser.readline()
    # print(raw_data)
    #
    # fin.write(struct.pack('<I', len(raw_data)-1))
    # fin.write(struct.pack('<I', len(raw_data)-1))
    # fin.write(raw_data[:-1])


    # len_data = ser.read(2)
    raw_data += ser.read(1)
    # print(struct.unpack('<H', len_data))
    # print(ser.read(1))
    print(raw_data)

    index += 1

frame_802_11 = raw_data.split('<<<80211FRAME>>>')

print(frame_802_11)
for pkt in frame_802_11:
    if len(pkt) != 0:
        pkt_list = list(struct.unpack('%dB' % len(pkt), pkt))
        pkt_len = pkt_list.pop(0) | pkt_list.pop(0) << 8

        if len(pkt_list) > 4:
            timestamp_esp32 = pkt_list.pop(0) | pkt_list.pop(0) << 8 | pkt_list.pop(0) << 16 | pkt_list.pop(0) << 24

            print("Current packet:")
            print("rx len = {}".format(pkt_len))
            print("timestamp = {}".format(timestamp_esp32))
            print(pkt_list)
            print("pkt_list len = {}".format(len(pkt_list)))
            print("\n")

            # pkt PCAP header
            fin.write(struct.pack('<I', timestamp_esp32 / 1000000))
            fin.write(struct.pack('<I', timestamp_esp32))

            fin.write(struct.pack('<I', pkt_len))
            fin.write(struct.pack('<I', pkt_len))

            fin.write(struct.pack('%dB' % len(pkt_list), *pkt_list))

        else:
            print("strange pkt")
            print(pkt_list)
            print("\n")

fin.close()
ser.close()