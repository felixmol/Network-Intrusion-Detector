# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# extractor Copyright(c) 2018 Félix Molina.
#
# Many thanks to Télécom SudParis (http://www.telecom-sudparis.eu)
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import pyshark
# import argparse
import flowlib

from datetime import datetime


def next_flow_id():
    global last_id_removed
    global last_id_assigned

    __next_id = last_id_assigned + 1
    last_id_assigned += 1

    if last_id_removed:
        __next_id = last_id_removed[0]
        last_id_removed.remove(__next_id)
        last_id_assigned -= 1

    return __next_id


def packet_callback(packet):
    global flow_list
    global next_id

    try:
        aggregation = False

        proto_value = flowlib.Packet.get_protocol(packet)
        pkt = flowlib.Packet(packet)

        for flw in flow_list:
            if flw.aggregate(pkt):
                aggregation = True
                break

        try:
            if aggregation is not True:
                if 'TCP' in proto_value[0]:
                    flow = flowlib.TCPFlow(next_id, packet.ip.src, packet.ip.dst, int(packet[proto_value[0]].srcport), int(
                            packet[proto_value[0]].dstport), int(proto_value[1]))
                    # If app_protocol known, add it
                    aggregation = flow.aggregate(pkt)
                    if aggregation:
                        flow_list += [flow]
                        next_id = next_flow_id()

                else:
                    flow = flowlib.Flow(next_id, packet.ip.src, packet.ip.dst, int(packet[proto_value[0]].srcport), int(
                            packet[proto_value[0]].dstport), int(proto_value[1]))
                    aggregation = flow.aggregate(pkt)
                    if aggregation:
                        flow_list += [flow]
                        next_id = next_flow_id()

        except Exception as e:
            print("Flow error : " + str(e))

    except Exception as e:
        print("Error : " + str(e))


def main():
    global flow_list

    start_time = datetime.now()

    # parser = argparse.ArgumentParser(description='Network feature extractor for RaspberryPi')
    # parser.add_argument("-i", "--iface", dest="iface", required=True, type=str, help="Network interface to sniff")
    # args = parser.parse_args(sys.argv)

    capture = pyshark.LiveCapture(interface='wlp2s0')  # args.iface)
    capture.set_debug(True)

    try:
        capture.apply_on_packets(packet_callback)
    except (Exception, KeyboardInterrupt):
        # print(str(e))
        pass
    finally:
        end_time = datetime.now()

        print("Number of flow recorded :\n\t" + str(last_id_assigned - len(last_id_removed)) if last_id_assigned >= 0
              else str(0) + " since " + str(start_time))
        print("Record duration :\n\t" + str(end_time - start_time))
        print("Close")


if __name__ == '__main__':
    flow_list = []
    last_id_removed = []
    last_id_assigned = -1
    next_id = 0
    main()
