#!/usr/bin/python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/

import click

import esp32pwn

# DEFAULT_TTY_ESP32           = '/dev/ttyUSB0'
# DEFAULT_TTY_ESP32_BAUDRATE  = 921600
# DEFAULT_WIFI_CHANNEL        = 5
#
# LINKTYPE_ETHERNET   = 0x1
# LINKTYPE_IEEE802_11 = 0x69      # http://www.tcpdump.org/linktypes.html
#
# # Global header of *.pcap file
# PCAP_MAGICAL_NUMBER = 0xA1B2C3D4
# PCAP_VERSION_MAJOR  = 0x2
# PCAP_VERSION_MINOR  = 0x4
# PCAP_THISZONE       = 0x0
# PCAP_SIGFIGS        = 0x0
# PCAP_SNAPLEN        = 0xFFFF
# PCAP_NETWORK        = LINKTYPE_IEEE802_11
#
#
# DATA_DELIMITER      = "<<<PARCEL>>>"
# FLAG_WIFI_PKT       = "<<<WiFi>>>"
# FLAG_REQ_SETTINGS   = "<<<RSTG>>>"
#
#
# PROMISCUOUS_FILTER = {
#                         1: "MGMT frame",
#                         2: "CTRL frame",
#                         4: "DATA frame"
#                      }



# class Esp32(object):
#
#     def __init__(self, tty, esp32_baudrate):
#         try:
#             self.ser = serial.Serial(tty, baudrate=esp32_baudrate)
#
#         except serial.SerialException as e:
#             self.ser = None
#             click.secho('e.strerror', bg='blue', fg='white')
#             exit(1)
#
#         else:
#             self.id_parcel = [FLAG_WIFI_PKT, FLAG_REQ_SETTINGS]
#
#     def __del__(self):
#         if self.ser:
#             self.ser.write(b'\x01\x01\x00')
#             self.ser.close()
#             click.secho('Promiscuous mode OFF', fg='magenta')
#
#     @staticmethod
#     def _analyze_rx_parcel(raw_data, type_parcel):
#
#         esp32_parcels = []
#         while True:
#
#             try:
#                 parcel_begin = raw_data.index(type_parcel.encode())
#
#             except ValueError:
#                 return esp32_parcels, raw_data
#
#             else:
#
#                 try:
#                     parcel_end = raw_data.index(DATA_DELIMITER.encode())
#
#                 except ValueError:
#                     return esp32_parcels, raw_data
#
#                 else:
#                     rx_parcel = raw_data[parcel_begin + len(type_parcel): parcel_end]
#
#                     raw_data = raw_data[parcel_end + len(DATA_DELIMITER):]
#
#                     if type_parcel == FLAG_WIFI_PKT:
#                         len_802_11 = rx_parcel[0] | (rx_parcel[1] << 8)
#                         t_msec_esp32 = rx_parcel[2] | (rx_parcel[3] << 8) | \
#                                        (rx_parcel[4] << 16) | (rx_parcel[5] << 24)  # get timestamp from ESP32
#
#                         if len_802_11 == len(rx_parcel[6:]):
#                             rx_802_11 = {'len': len_802_11,
#                                          'time': t_msec_esp32,
#                                          'frame': rx_parcel[6:]}
#
#                             esp32_parcels.append(rx_802_11)
#
#                             if len(raw_data) == 0:
#                                 return esp32_parcels, b""
#
#                     elif type_parcel == FLAG_REQ_SETTINGS:
#                         return rx_parcel, raw_data
#
#     def get_settings(self, name=None):
#         """
#         To communicate with ESP32 is used TLV protocol (Type-Length-Value)
#         :param name:    what we ask
#                             for channel Wi-Fi   TLV - 0x2:0x1:0x0
#                             for mask            TLV - 0x2:0x1:0x1
#
#         """
#         if name == 'channel':
#             self.ser.write(b'\x02\x01\x00')
#
#         elif name == 'mask':
#             self.ser.write(b'\x02\x01\x01')
#
#         elif name == 'ap':
#             self.ser.write(b'\x02\x01\x02')
#
#         else:
#             return name, False
#             print("Unknown parametre")
#
#         attempt = 0
#         self.ser.timeout = 0.1
#         raw_data = b""
#
#         while attempt < 10:
#
#             raw_data += self.ser.read_until(terminator=DATA_DELIMITER)
#             # print(raw_data)
#
#             settings, rest_bytes = self._analyze_rx_parcel(raw_data, FLAG_REQ_SETTINGS)
#
#             if len(settings) > 0:
#                 if settings[0] == 0 and (len(settings) > 0):
#                     return name, settings[1]
#
#                 elif settings[0] == 1 and (len(settings) > 0):
#                     mask = (settings[1] << 24) | (settings[2] << 16) | (settings[3] << 8) | settings[4]
#                     return name, mask
#
#             attempt += 1
#
#         click.secho("{} attempts were made to request '{}'".format(attempt, name), fg='cyan')
#         return name, False
#
#     def set_settings(self, type_settings, value):
#         if type_settings == 'channel':
#             self.ser.write(struct.pack('4B', 0x3, 0x2, 0x1, value))
#
#         elif type_settings == 'pkt_type':
#             if value == 'MGMT':
#                 self.ser.write(b'\x03\x02\x02\x00')
#
#             elif value == 'CTRL':
#                 self.ser.write(b'\x03\x02\x02\x01')
#                 # self.ser.write(b'\x04\x01\x01')
#
#             elif value == 'DATA':
#                 self.ser.write(b'\x03\x02\x02\x02')
#                 # self.ser.write(b'\x04\x01\x02')
#
#             elif value == 'ALL':
#                 self.ser.write(b'\x03\x02\x02\x03')
#                 # self.ser.write(b'\x04\x01\x03')
#
#             else:
#                 click.secho("At this moment this type of filter {} doesn't support".format(value), bg='blue', fg='white')
#
#     def sniff_wifi(self, user_pcap, total_pkt):
#
#         self.ser.write(b'\x01\x01\x01')
#
#         pcap_file = user_pcap.split('.')
#
#         pcap_file = pcap_file[0] + ".pcap"
#
#         fin = open(pcap_file, "wb")
#
#         fin.write(struct.pack('<I', PCAP_MAGICAL_NUMBER))
#         fin.write(struct.pack('<H', PCAP_VERSION_MAJOR))
#         fin.write(struct.pack('<H', PCAP_VERSION_MINOR))
#         fin.write(struct.pack('<I', PCAP_THISZONE))
#         fin.write(struct.pack('<I', PCAP_SIGFIGS))
#         fin.write(struct.pack('<I', PCAP_SNAPLEN))
#         fin.write(struct.pack('<I', PCAP_NETWORK))
#
#         current_pkt = 0
#         self.ser.timeout = 0.1
#
#         raw_data = b""
#
#         while current_pkt < total_pkt:
#
#             raw_data += self.ser.read_until(terminator=DATA_DELIMITER)
#
#             frames_802_11, rest_bytes = self._analyze_rx_parcel(raw_data, FLAG_WIFI_PKT)
#
#             for frame in frames_802_11:
#
#                 # pkt PCAP header
#                 fin.write(struct.pack('<I', frame['time'] // 1000000))
#                 fin.write(struct.pack('<I', frame['time']))
#
#                 fin.write(struct.pack('<I', frame['len']))
#                 fin.write(struct.pack('<I', frame['len']))
#
#                 fin.write(struct.pack('%dB' % frame['len'], *frame['frame']))
#
#                 current_pkt += 1
#                 addr_mac1 = ':'.join("{:02X}".format(i) for i in frame['frame'][4:10])
#                 addr_mac2 = ':'.join("{:02X}".format(i) for i in frame['frame'][10:16])
#                 addr_mac3 = ':'.join("{:02X}".format(i) for i in frame['frame'][16:22])
#
#                 print("{:>5}  {}  {}  {}".format(current_pkt, addr_mac1, addr_mac2, addr_mac3))
#
#             raw_data = rest_bytes
#
#         fin.close()


@click.group()
def main():
    pass


@click.command()
@click.option('-tty',
              default=esp32pwn.DEFAULT_TTY_ESP32,
              help='Serial port where connected esp32pwn_old default = {}'.format(esp32pwn.DEFAULT_TTY_ESP32))
@click.option('-bd', '--baudrate', 'bd',
              default=str(esp32pwn.DEFAULT_TTY_ESP32_BAUDRATE),
              type=click.Choice(['115200', '921600']),
              help='Setup baudrate; default = {}'.format(esp32pwn.DEFAULT_TTY_ESP32_BAUDRATE))
@click.option('-s', '--setting', 'feature',
              type=click.Choice(['channel', 'mask', 'ap']),
              help="Request Wi-Fi channel and which Wi-Fi pkt filtered")
def get(tty, bd, feature):
    esp32_board = esp32pwn.Esp32(tty, int(bd))
    request_attribute, attribute_value = esp32_board.get_settings(feature)

    if request_attribute == 'channel' and attribute_value:
        click.secho("Current channel: {}".format(attribute_value))

    elif request_attribute == "mask" and attribute_value:
        try:
            print("ESP32 receive next pkt : {}".format(esp32pwn.PROMISCUOUS_FILTER[attribute_value]))

        except KeyError:
            click.secho('Unknown filter mask - {:X}'.format(attribute_value), fg='yellow')

    elif request_attribute == 'ap' and attribute_value:

        print("{:>11} {:>20}                            | Channel | RSSI |   Auth Mode ".format('BSSID', 'SSID'))
        # print(" BSSID              SSID              | Channel | RSSI |   Auth Mode \n");
        for ap in attribute_value:
            bssid = ":".join("{:02X}".format(i) for i in ap['bssid'])
            ssid = ap['ssid']
            print("{} {:>32}".format(bssid, ssid))
            # print("{:>32s}".format( ssid))
        # print(attribute_value)
    else:
        click.secho("Can't understand - {:X}".format(attribute_value), fg='yellow')
        pass


@click.command()
@click.option('-tty',
              default=esp32pwn.DEFAULT_TTY_ESP32,
              help='Serial port where connected esp32pwn_old default = {}'.format(esp32pwn.DEFAULT_TTY_ESP32))
@click.option('-bd', '--baudrate', 'bd',
              default=str(esp32pwn.DEFAULT_TTY_ESP32_BAUDRATE),
              type=click.Choice(['115200', '921600']),
              help='Setup baudrate; default = {}'.format(esp32pwn.DEFAULT_TTY_ESP32_BAUDRATE))
@click.option('-c', '--channel', 'channel',
              type=click.IntRange(1, 14),
              help="Wi-Fi channel, range [1 ... 13]")
@click.option('-f', '--filter', 'pkt_type',
              type=click.Choice(['ALL', 'MGMT', 'CTRL', 'DATA']),
              help="Set filter which type of packet receive")
def set(tty, bd, channel, pkt_type):
    esp32_board = esp32pwn.Esp32(tty, int(bd))
    if channel:
        esp32_board.set_settings('channel', channel)

    if pkt_type:
        esp32_board.set_settings('pkt_type', pkt_type)


@click.command()
@click.option('-tty',
              default=esp32pwn.DEFAULT_TTY_ESP32,
              help='Serial port where connected esp32pwn_old default = {}'.format(esp32pwn.DEFAULT_TTY_ESP32))
@click.option('-bd', '--baudrate', 'bd',
              default=str(esp32pwn.DEFAULT_TTY_ESP32_BAUDRATE),
              type=click.Choice(['115200', '921600']),
              help='Setup baudrate; default = {}'.format(esp32pwn.DEFAULT_TTY_ESP32_BAUDRATE))
@click.option('-c', '--channel', 'channel',
              type=click.IntRange(1, 14),
              help="Wi-Fi channel, range [1 ... 13]")
@click.option('-f', '--filter', 'pkt_type',
              type=click.Choice(['ALL', 'MGMT', 'CTRL', 'DATA']),
              help="Set filter which type of packet receive")
@click.option('-pcap',
              default='esp32pwn_old',
              help='Name of file to store result')
@click.option('-n',
              default=500,
              type=click.INT,
              help="How many packets to capture")
def run(tty, bd, channel, pkt_type, pcap, n):
    esp32_board = esp32pwn.Esp32(tty, int(bd))
    esp32_board.sniff_wifi(pcap, n)


main.add_command(get)
main.add_command(set)
main.add_command(run)


if __name__ == '__main__':
    try:
        main()
    except click.ClickException as e:
        print(e.message)

