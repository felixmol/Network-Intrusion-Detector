# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# pi-extractor (c) 2018 Félix Molina.
#
# Many thanks to Télécom SudParis (http://www.telecom-sudparis.eu) for
# its material support of this effort.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#

import pyshark
# import argparse
import flowlib


def packet_callback(packet):
    global flow_list

    try:
        proto_value = flowlib.Packet.get_protocol(packet)
        pkt = flowlib.Packet(packet)

        for flw in flow_list:
            if flw.aggregate(pkt):
                break
            elif 'TCP' in proto_value[0]:
                flow = flowlib.TCPFlow(packet.ip.src, packet.ip.dst, int(packet[proto_value[0]].srcport), int(packet[
                      proto_value[0]].dstport), int(proto_value[1]))
                # If app_protocol known, add it
                flow.aggregate(pkt)
                flow_list += [flow]

    except Exception as e:
        print("Bad protocol : " + str(e))


def main():
    global flow_list

    # parser = argparse.ArgumentParser(description='Network feature extractor for RaspberryPi')
    # parser.add_argument("-i", "--iface", dest="iface", required=True, type=str, help="Network interface to sniff")
    # parsed_command = parser.parse_args(sys.argv)

    capture = pyshark.LiveCapture(interface='wlp2s0')  # parsed_command.iface)
    capture.set_debug(True)

    try:
        capture.apply_on_packets(packet_callback)
    except Exception as e:
        print(str(e))
        print("Nb Flow = " + str(len(flow_list)))
        print("Close")


if __name__ == '__main__':
    flow_list = []
    main()
