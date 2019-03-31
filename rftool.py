#!/usr/bin/python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/

import click

import esp32pwn


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

        print(" {:^17}  {}  {}  {:^15}  {}  {}  {:^32}".format('BSSID', 'Channel', 'RSSI', 'Auth Mode', 'B G N LR', 'WPS', 'SSID'))

        for ap in attribute_value:
            bssid = ":".join("{:02X}".format(i) for i in ap['bssid'])
            ssid = ap['ssid'].split('\x00')[0]
            channel = ap['channel']
            rssi = (256 - ap['rssi']) * (-1)
            authmode = esp32pwn.WIFI_AUTH_MODE[ap['authmode']]
            phy_b = (ap['phy_bgn'] & 0x1)
            phy_g = (ap['phy_bgn'] & 0x2) >> 1
            phy_n = (ap['phy_bgn'] & 0x4) >> 2
            phy_lr = (ap['phy_bgn'] & 0x8) >> 3
            phy_wps = (ap['phy_bgn'] & 0x10) >> 4

            phy = ' '.join([str(phy_b), str(phy_g), str(phy_n), str(phy_lr)])

            if phy_wps or authmode == 'OPEN':
                click.secho(" {}  {:^7}  {:^4}  {:<15}  {}  {:^5}  {}".format(bssid,
                                                                              channel,
                                                                              rssi,
                                                                              authmode,
                                                                              phy,
                                                                              phy_wps,
                                                                              ssid), fg='cyan')

            else:
                print(" {}  {:^7}  {:^4}  {:<15}  {}  {:^5}  {}".format(bssid,
                                                                        channel,
                                                                        rssi,
                                                                        authmode,
                                                                        phy,
                                                                        phy_wps,
                                                                        ssid))
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

