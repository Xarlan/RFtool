import serial
import struct
import datetime


ser = serial.Serial('/dev/ttyUSB0', baudrate=115200)
# print ser.read(10)
# ser.write(b'helloqwert\n')

LINKTYPE_ETHERNET   = 0x1
LINKTYPE_IEEE802_11 = 0x69      # http://www.tcpdump.org/linktypes.html

# Global header of *.pcap file
PCAP_MAGICAL_NUMBER = 0xA1B2C3D4
PCAP_VERSION_MAJOR  = 0x2
PCAP_VERSION_MINOR  = 0x4
PCAP_THISZONE       = 0x0
PCAP_SIGFIGS        = 0x0
PCAP_SNAPLEN        = 0xFFFF
PCAP_NETWORK        = LINKTYPE_IEEE802_11
# PCAP_NETWORK        = LINKTYPE_ETHERNET

fin = open("esp32.pcap", "wb")

fin.write(struct.pack('<I', PCAP_MAGICAL_NUMBER))
fin.write(struct.pack('<H', PCAP_VERSION_MAJOR))
fin.write(struct.pack('<H', PCAP_VERSION_MINOR))
fin.write(struct.pack('<I', PCAP_THISZONE))
fin.write(struct.pack('<I', PCAP_SIGFIGS))
fin.write(struct.pack('<I', PCAP_SNAPLEN))
fin.write(struct.pack('<I', PCAP_NETWORK))

index = 0

while index < 10:
    # pkt header
    fin.write(struct.pack('<I', datetime.datetime.now().second))
    fin.write(struct.pack('<I', datetime.datetime.now().microsecond))

    # raw_len_pkt = struct.unpack('3B', ser.readline())
    # len_pkt = (raw_len_pkt[1] << 8) | raw_len_pkt[0]

    # print("len pkt = {}".format(len_pkt))
    # print("len pkt = {}".format(struct.unpack('3B', len_pkt)))

    # fin.write(struct.pack('<I', len_pkt))
    # fin.write(struct.pack('<I', len_pkt))

    # raw_data = ser.read(len_pkt)
    raw_data = ser.readline()
    print(raw_data)

    fin.write(struct.pack('<I', len(raw_data)-1))
    fin.write(struct.pack('<I', len(raw_data)-1))
    fin.write(raw_data[:-1])

    index += 1

fin.close()
ser.close()

