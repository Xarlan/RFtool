#!/usr/bin/python3

import serial
import struct
import datetime
import click
# import logging


DEFAULT_TTY_ESP32           = '/dev/ttyUSB0'
DEFAULT_TTY_ESP32_BAUDRATE  = 921600
DEFAULT_WIFI_CHANNEL        = 5

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


DATA_DELIMITER      = "<<<PARCEL>>>"
FLAG_WIFI_PKT       = "<<<WiFi>>"
FLAG_REQ_SETTINGS   = "<<<RSTG>>>"

# ESP32_SETTINGS = {
#                     0: "Current Wi-Fi channel",
#                     1: "Current MASK"}

PROMISCUOUS_FILTER = {
                        1: "MGMT frame",
                        2: "CTRL frame",
                        4: "DATA frame"
                     }


class Esp32(object):

    def __init__(self, tty, esp32_baudrate):
        try:
            self.ser = serial.Serial(tty, baudrate=esp32_baudrate)

        except serial.SerialException as e:
            self.ser = None
            # click.echo(click.style(e.strerror, bg='blue', fg='white'))
            click.secho('e.strerror', bg='blue', fg='white')
            exit(1)

        else:
            self.id_parcel = [FLAG_WIFI_PKT, FLAG_REQ_SETTINGS]

    def __del__(self):
        if self.ser:
            self.ser.close()

    def _check_rx_parcel(self, raw_pkt):

        for parcel in self.id_parcel:

            try:
                index_id = raw_pkt.index(parcel)

            except ValueError:
                pass
                # print("Unknown parcel")
                # print(raw_pkt)

            else:
                raw_pkt = raw_pkt[index_id + len(parcel):0 - len(DATA_DELIMITER)]
                raw_pkt = struct.unpack('%dB' % len(raw_pkt), raw_pkt.encode())

                if parcel == FLAG_WIFI_PKT:
                    pass

                elif parcel == FLAG_REQ_SETTINGS:
                    # settings = {ESP32_SETTINGS[raw_pkt[0]] : raw_pkt[1]}
                    # return settings
                    return raw_pkt

                # len_raw_pkt = raw_pkt[0] | (raw_pkt[1] << 8)
                # t_msec_esp32 = raw_pkt[2] | (raw_pkt[3] << 8) | (raw_pkt[4] << 16) | (raw_pkt[5] << 24)  # get timestamp
                # # from ESP32
                #
                # if len_raw_pkt == len(raw_pkt[6:]):
                #     rx_802_11 = {'len': len_raw_pkt,
                #                  'time': t_msec_esp32,
                #                  'frame': raw_pkt[6:]}
                #     return rx_802_11

    def get_settings(self, name=None):
        """
        To communicate with ESP32 is used TLV protocol (Type-Length-Value)
        :param name:    what we ask
                            for channel Wi-Fi   TLV - 0x2:0x1:0x0
                            for mask            TLV - 0x2:0x1:0x1

        """
        if name == 'channel':
            self.ser.write(b'\x02\x01\x00')

        elif name == 'mask':
            self.ser.write(b'\x02\x01\x01')

        else:
            print("Unknown parametre")

        index = 0
        self.ser.timeout = 0.1

        while index < 4:

            raw_frame = self.ser.read_until(terminator=DATA_DELIMITER)

            if raw_frame:
                frame = self._check_rx_parcel(raw_frame.decode())

                if frame[0] == 0:
                    print("Current channel : {}".format(frame[1]))
                    exit(0)

                elif frame[0] == 1:
                    mask = (frame[1] << 24) | (frame[2] << 16) | (frame[3] << 8) | frame[4]
                    try:
                        print("ESP32 receive next frame : {}".format(PROMISCUOUS_FILTER[mask]))

                    except KeyError:
                        click.secho('Unknown filter mask - {:X}'.format(mask), fg='yellow')
                    exit(0)

            index += 1

        click.secho('An unknown property was requested', bg='blue', fg='white')

    def set_settings(self, type_settings, value):
        if type_settings == 'channel':
            self.ser.write(struct.pack('3B', 0x3, 0x1, value))
        elif type_settings == 'pkt_type':
            pass



# ser = serial.Serial('/dev/ttyUSB0', baudrate=115200)
# # print ser.read(10)
# # ser.write(b'helloqwert\n')
#

#
# fin = open("esp32new.pcap", "wb")
#
# fin.write(struct.pack('<I', PCAP_MAGICAL_NUMBER))
# fin.write(struct.pack('<H', PCAP_VERSION_MAJOR))
# fin.write(struct.pack('<H', PCAP_VERSION_MINOR))
# fin.write(struct.pack('<I', PCAP_THISZONE))
# fin.write(struct.pack('<I', PCAP_SIGFIGS))
# fin.write(struct.pack('<I', PCAP_SNAPLEN))
# fin.write(struct.pack('<I', PCAP_NETWORK))
#
# index = 0
#
# while index < 10:
#     # pkt header
#     fin.write(struct.pack('<I', datetime.datetime.now().second))
#     fin.write(struct.pack('<I', datetime.datetime.now().microsecond))
#
#     # raw_len_pkt = struct.unpack('3B', ser.readline())
#     # len_pkt = (raw_len_pkt[1] << 8) | raw_len_pkt[0]
#
#     # print("len pkt = {}".format(len_pkt))
#     # print("len pkt = {}".format(struct.unpack('3B', len_pkt)))
#
#     # fin.write(struct.pack('<I', len_pkt))
#     # fin.write(struct.pack('<I', len_pkt))
#
#     # raw_data = ser.read(len_pkt)
#     raw_data = ser.readline()
#     print(raw_data)
#
#     fin.write(struct.pack('<I', len(raw_data)-1))
#     fin.write(struct.pack('<I', len(raw_data)-1))
#     fin.write(raw_data[:-1])
#
#     index += 1
#
# fin.close()
# ser.close()


@click.group()
def main():
    pass


@click.command()
@click.option('-tty',
              default=DEFAULT_TTY_ESP32,
              help='Serial port where connected esp32 default = {}'.format(DEFAULT_TTY_ESP32))
@click.option('-bd', '--baudrate', 'bd',
              default=str(DEFAULT_TTY_ESP32_BAUDRATE),
              type=click.Choice(['115200', '921600']),
              help='Setup baudrate; default = {}'.format(DEFAULT_TTY_ESP32_BAUDRATE))
@click.option('-s', '--setting', 'feature',
              type=click.Choice(['channel', 'mask']),
              help="Request Wi-Fi channel and which Wi-Fi pkt filtered")
def get(tty, bd, feature):
    esp32 = Esp32(tty, int(bd))
    esp32.get_settings(feature)


@click.command()
@click.option('-tty',
              default=DEFAULT_TTY_ESP32,
              help='Serial port where connected esp32 default = {}'.format(DEFAULT_TTY_ESP32))
@click.option('-bd', '--baudrate', 'bd',
              default=str(DEFAULT_TTY_ESP32_BAUDRATE),
              type=click.Choice(['115200', '921600']),
              help='Setup baudrate; default = {}'.format(DEFAULT_TTY_ESP32_BAUDRATE))
@click.option('-c', '--channel', 'channel',
              type=click.IntRange(1, 14),
              help="Wi-Fi channel, range [1 ... 13]")
@click.option('-f', '--filter', 'pkt_type',
              type=click.Choice(['ALL', 'MGMT', 'CTRL', 'DATA']),
              help="Set filter which type of packet receive")
def set(tty, bd, channel, pkt_type):
    esp32 = Esp32(tty, int(bd))
    if channel:
        esp32.set_settings('channel', channel)
    if pkt_type:
        esp32.set_settings('pkt_type', pkt_type)


@click.command()
@click.option('-tty',
              default=DEFAULT_TTY_ESP32,
              help='Serial port where connected esp32 default = {}'.format(DEFAULT_TTY_ESP32))
@click.option('-bd', '--baudrate', 'bd',
              default=str(DEFAULT_TTY_ESP32_BAUDRATE),
              type=click.Choice(['115200', '921600']),
              help='Setup baudrate; default = {}'.format(DEFAULT_TTY_ESP32_BAUDRATE))
@click.option('-c', '--channel', 'channel',
              type=click.IntRange(1, 14),
              help="Wi-Fi channel, range [1 ... 13]")
@click.option('-f', '--filter', 'pkt_type',
              type=click.Choice(['ALL', 'MGMT', 'CTRL', 'DATA']),
              help="Set filter which type of packet receive")
@click.option('-pcap',
              default='esp32',
              help='Name of file to store result')
@click.option('-n',
              default=500,
              type=click.INT,
              help="How many packets to capture")
def run(tty, bd, channel, pkt_type, pcap, n):
    pass


# @click.command()
# @click.option('-ch', default=1, type=click.IntRange(1, 13), help="Select Wi-Fi channel, default channel = 1")
# @click.option('-n', default=10, type=click.INT, help="How many packets to capture")
# @click.option('-tty', default=DEFAULT_TTY_ESP32, help='Serial port where connected esp32')
# @click.option('-bd', default=DEFAULT_TTY_ESP32_BAUDRATE, help='Setup baudrate', type=click.Choice([115200, 921600]))
# @click.option('-pcap', default='esp32', help='Name of file to store result')
# def run(ch, n, tty, bd, pcap):
#     try:
#         ser = serial.Serial(tty, baudrate=115200)
#
#     except serial.SerialException as e:
#         print(e.strerror)
#
#     else:
#         fin = open(''.join((pcap, '.pcap')), "wb")
#
#         fin.write(struct.pack('<I', PCAP_MAGICAL_NUMBER))
#         fin.write(struct.pack('<H', PCAP_VERSION_MAJOR))
#         fin.write(struct.pack('<H', PCAP_VERSION_MINOR))
#         fin.write(struct.pack('<I', PCAP_THISZONE))
#         fin.write(struct.pack('<I', PCAP_SIGFIGS))
#         fin.write(struct.pack('<I', PCAP_SNAPLEN))
#         fin.write(struct.pack('<I', PCAP_NETWORK))
#
#         index = 0
#         while index < n:
#             # pkt header
#             fin.write(struct.pack('<I', datetime.datetime.now().second))
#             fin.write(struct.pack('<I', datetime.datetime.now().microsecond))
#
#             # raw_len_pkt = struct.unpack('3B', ser.readline())
#             # len_pkt = (raw_len_pkt[1] << 8) | raw_len_pkt[0]
#
#             # print("len pkt = {}".format(len_pkt))
#             # print("len pkt = {}".format(struct.unpack('3B', len_pkt)))
#
#             # fin.write(struct.pack('<I', len_pkt))
#             # fin.write(struct.pack('<I', len_pkt))
#
#             # raw_data = ser.read(len_pkt)
#             raw_data = ser.readline()
#             print(raw_data)
#
#             fin.write(struct.pack('<I', len(raw_data)-1))
#             fin.write(struct.pack('<I', len(raw_data)-1))
#             fin.write(raw_data[:-1])
#
#             index += 1
#
#         print("Current baudrate = {}".format(bd))
#         ser.close()
#
#


main.add_command(get)
main.add_command(set)
# main.add_command(run)


if __name__ == '__main__':
    try:
        main()
    except click.ClickException as e:
        print(e.message)
    # except TypeError as e:
    #     print(e)

