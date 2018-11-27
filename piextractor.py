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
import flowsender
import os
import signal

from time import sleep
from multiprocessing import Process, Manager
from datetime import datetime


def put_in_send_list(flow):
    global send_list

    send_list[flow.get_flow_id()] = flow.to_dict_format()


def send_flow(address, port, interval):
    global send_list

    while 1:
        try:
            sleep(interval)
            if len(send_list.keys()) != 0:
                try:
                    flowsender.send_data(address=address, port=port, flows=send_list.copy())
                    send_list.clear()
                except flowsender.SendingFlowsException as ex:
                    print(str(ex))
                    pass
        except (Exception, KeyboardInterrupt):
            break


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

        for flw in flow_list.values():
            if flw.aggregate(pkt):
                put_in_send_list(flw)
                aggregation = True
                break

        try:
            if aggregation is not True:
                if 'TCP' in proto_value[0]:
                    flow = flowlib.TCPFlow(next_id, packet.ip.src, packet.ip.dst, int(packet[proto_value[0]].srcport),
                                           int(packet[proto_value[0]].dstport), int(proto_value[1]))
                    # If app_protocol known, add it
                    aggregation = flow.aggregate(pkt)
                    if aggregation:
                        flow_list[flow.get_flow_id()] += flow
                        put_in_send_list(flow)
                        next_id = next_flow_id()

                else:
                    flow = flowlib.Flow(next_id, packet.ip.src, packet.ip.dst, int(packet[proto_value[0]].srcport), int(
                                        packet[proto_value[0]].dstport), int(proto_value[1]))
                    aggregation = flow.aggregate(pkt)
                    if aggregation:
                        flow_list[flow.get_flow_id()] += flow
                        put_in_send_list(flow)
                        next_id = next_flow_id()

        except Exception as ec:
            print("Flow error : " + str(ec))

    except Exception as exc:
        print("Error : " + str(exc))


def main(iface: str):
    global flow_list

    start_time = datetime.now()

    capture = pyshark.LiveCapture(interface=iface)  # args.iface)
    capture.set_debug(True)

    # args.server_address, args.server_port, args.sending_interval, args.kwargs

    try:
        capture.apply_on_packets(packet_callback)
    except (Exception, KeyboardInterrupt):
        pass
    finally:
        end_time = datetime.now()

        print("Number of flow recorded :\n\t" + str(last_id_assigned - len(last_id_removed)) if last_id_assigned >= 0
              else str(0) + " since " + str(start_time))
        print("Record duration :\n\t" + str(end_time - start_time))
        print("Close")


if __name__ == '__main__':
    # parser = argparse.ArgumentParser(description='Network feature extractor for RaspberryPi')
    # parser.add_argument("-i", "--iface", dest="iface", required=True, type=str, help="Network interface to sniff")
    # parser.add_argument("-a", "--server-address", dest="server_address", required=True, type=str, help="Address of the
    # collector")
    # parser.add_argument("-p", "--server-port", dest="server_port", required=True, type=int, help="Listening port of
    # the collector")
    # parser.add_argument("-r", "--interval", dest="sending_interval", required=True, type=int, help="Sending interval")
    # parser.add_argument("-k", "--kwargs", dest="kwargs", required=True, type=tuple, help="Additional arguments")
    # args = parser.parse_args(sys.argv)

    flow_list = {}
    last_id_removed = []
    last_id_assigned = -1
    next_id = 0

    manager = Manager()
    send_list = manager.dict()

    if not flowsender.check_ipv4_address("127.0.0.1"):
        exit(1)

    print("Collector at " + "127.0.0.1" + ":" + str(8888))

    sending_process = Process(name="Flow sending process", target=send_flow, args=("127.0.0.1", 8888, 3))
    sending_process.start()

    main('wlp2s0')

    sending_process.join(0)
    manager.join(0)

    if sending_process.is_alive():
        os.kill(sending_process.pid, signal.SIGKILL)

    print("Thread closed")
