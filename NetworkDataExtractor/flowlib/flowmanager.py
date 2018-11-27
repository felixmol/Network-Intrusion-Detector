# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# flow manager Copyright(c) 2018 Félix Molina.
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

import flowlib
import signal
import os
from multiprocessing import Manager
from threading import Timer


class FlowManager(object):

    def __init__(self):
        super().__init__()

        self.__manager = Manager()
        self.__flow_list = self.__manager.dict()
        self.__send_list = self.__manager.dict()
        self.__last_ids_removed = self.__manager.list()

        self.__last_id_assigned = -1
        self.__next_id = 0
        self.__ids_removed_length = 0

        self.__counters = flowlib.COUNTERS

        self.__flow_timers = {}
        self.__flow_duration = 10

        self.__sending_service = flowlib.FlowSender("127.0.0.1", 8888, 3, self.__send_list)
        self.__deletion_service = flowlib.FlowDeletion(60, self.__flow_list, self.__last_ids_removed)

    def __next_flow_id(self):
        __next_id = self.__last_id_assigned + 1
        self.__last_id_assigned += 1

        if len(self.__last_ids_removed) is not 0:
            __next_id = self.__last_ids_removed[0]
            self.__last_ids_removed.remove(__next_id)
            self.__last_id_assigned -= 1

        self.__ids_removed_length = len(self.__last_ids_removed)

        return __next_id

    def __timer_trigger(self, flow):
        self.__flow_timers[flow.get_flow_id()] = Timer(interval=self.__flow_duration,
                                                       function=self.__close_flow,
                                                       args=(flow.get_flow_id(), True))
        self.__flow_timers[flow.get_flow_id()].start()

    def __close_flow(self, flow_id, by_timer = True):
        self.__flow_list[flow_id].close_flow()
        self.put_in_send_list(self.__flow_list[flow_id])

        if not by_timer:
            self.__flow_timers[flow_id].cancel()
            self.__flow_timers.pop(flow_id, None)

    def add_flow(self, flow):
        self.__flow_list[flow.get_flow_id()] = flow

    def put_in_send_list(self, flow):
        self.__send_list[flow.get_flow_id()] = flow.to_dict_format()

    def counter_calculation(self, source_ip: str, destination_ip: str, source_port: int, destination_port: int):
        ct_dst_src_ltm_hash = hash(destination_ip + source_ip)
        ct_src_dport_ltm_hash = hash(source_ip + str(destination_port))
        ct_dst_ltm_hash = hash(destination_ip)
        ct_dst_sport_ltm_hash = hash(destination_ip + str(source_port))

        if len(self.__counters["ct_dst_src_ltm"]) >= 100:
            self.__counters["ct_dst_src_ltm"].pop()
        self.__counters["ct_dst_src_ltm"].insert(0, ct_dst_src_ltm_hash)

        if len(self.__counters["ct_src_dport_ltm"]) >= 100:
            self.__counters["ct_src_dport_ltm"].pop()
        self.__counters["ct_src_dport_ltm"].insert(0, ct_src_dport_ltm_hash)

        if len(self.__counters["ct_dst_ltm"]) >= 100:
            self.__counters["ct_dst_ltm"].pop()
        self.__counters["ct_dst_ltm"].insert(0, ct_dst_ltm_hash)

        if len(self.__counters["ct_dst_sport_ltm"]) >= 100:
            self.__counters["ct_dst_sport_ltm"].pop()
        self.__counters["ct_dst_sport_ltm"].insert(0, ct_dst_sport_ltm_hash)

        return {
            "ct_dst_src_ltm": self.__counters["ct_dst_src_ltm"].count(ct_dst_src_ltm_hash),
            "ct_src_dport_ltm": self.__counters["ct_src_dport_ltm"].count(ct_src_dport_ltm_hash),
            "ct_dst_ltm": self.__counters["ct_dst_ltm"].count(ct_dst_ltm_hash),
            "ct_dst_sport_ltm": self.__counters["ct_dst_sport_ltm"].count(ct_dst_sport_ltm_hash)
        }

    def packet_analysis(self, packet):
        try:
            aggregation = False

            proto_value = flowlib.Packet.get_protocol(packet)
            pkt = flowlib.Packet(packet)

            for flow in self.__flow_list.values():
                if flow.aggregate(pkt):
                    self.put_in_send_list(flow)
                    aggregation = True
                    break

            try:
                if aggregation is not True:
                    if 'TCP' in proto_value[0]:
                        flow = flowlib.TCPFlow(self.__next_id, packet.ip.src, packet.ip.dst, int(packet[proto_value[
                            0]].srcport), int(packet[proto_value[0]].dstport), int(proto_value[1]))
                        # If app_protocol known, add it
                    else:
                        flow = flowlib.Flow(self.__next_id, packet.ip.src, packet.ip.dst, int(packet[proto_value[0]].srcport),
                                            int(packet[proto_value[0]].dstport), int(proto_value[1]))

                    aggregation = flow.aggregate(pkt, counters=self.counter_calculation(packet.ip.src, packet.ip.dst,
                                            int(packet[proto_value[0]].srcport), int(packet[proto_value[0]].dstport)))
                    if aggregation:
                        self.add_flow(flow)
                        self.put_in_send_list(flow)
                        self.__timer_trigger(flow)
                        self.__next_id = self.__next_flow_id()

            except Exception as ec:
                print("Flow error : " + str(ec))

        except Exception as exc:
            print("Error : " + str(exc))

    def start_service(self):
        self.__sending_service.start()
        print("[+] Sending service started")
        self.__deletion_service.start()
        print("[+] Deletion service started")

    def stop_service(self):
        print("Stopping services...")
        for timer in self.__flow_timers.values():
            timer.cancel()

        self.__sending_service.join(10)
        #if self.__sending_service.is_alive():
        #    self.__sending_service.join(10)
        #    os.kill(self.__sending_service.pid, signal.SIGKILL)
        print("[-] Sending service stopped")

        self.__deletion_service.join(10)
        #if self.__deletion_service.is_alive():
        #    self.__deletion_service.join(10)
        #    os. (self.__deletion_service.pid, signal.SIGKILL)
        print("[-] Deletion service stopped")

        print("\nNumber of flow recorded :\n\t" + str((self.__last_id_assigned - self.__ids_removed_length)
                                                    if self.__last_id_assigned >= 0 else 0))
