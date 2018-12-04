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

from threading import Timer
from idsconfigparser import SettingParser
import flowlib
import multiprocessing


class FlowManager(object):

    def __init__(self, config: SettingParser = SettingParser()):
        super().__init__()

        self.__setting_parser = config

        self.__flow_list = dict()
        self.__send_list = multiprocessing.Queue()
        self.__remove_list = multiprocessing.Queue()
        self.__last_ids_removed = multiprocessing.Queue()

        self.__last_id_assigned = -1
        self.__next_id = 0
        self.__ids_removed_length = 0

        self.__counters = flowlib.COUNTERS

        self.__flow_timers = {}
        self.__flow_duration = 30
        self.__number_of_flow = 0

        self.__sending_service = flowlib.FlowSender(
            address=self.__setting_parser.get_str_value("COLLECTOR", "IpAddress", "127.0.0.1"),
            port=self.__setting_parser.get_int_value("COLLECTOR", "Port", 8888),
            interval=self.__setting_parser.get_int_value("EXTRACTOR", "SendingInterval", 5),
            data=self.__send_list)

        self.__deletion_service = flowlib.FlowDeletion(
            interval=self.__setting_parser.get_int_value("EXTRACTOR", "DeletionInterval", 60),
            data=self.__remove_list,
            id_list=self.__last_ids_removed)

    def __next_flow_id(self):
        __next_id = self.__last_id_assigned + 1
        self.__last_id_assigned += 1

        if not self.__last_ids_removed.empty():
            __next_id = self.__last_ids_removed.get()
            self.__last_id_assigned -= 1

        self.__ids_removed_length = self.__last_ids_removed.qsize()

        return __next_id

    def __timer_trigger(self, flow):
        self.__flow_timers[flow.get_flow_id()] = Timer(interval=self.__flow_duration,
                                                       function=self.__close_flow,
                                                       args=(flow.get_flow_id(), True))
        self.__flow_timers[flow.get_flow_id()].start()

    def __close_flow(self, flow_id, by_timer=True):
        try:
            self.__flow_list[flow_id].close_flow()
            self.put_in_send_list(self.__flow_list[flow_id])
            self.put_in_remove_list(self.__flow_list[flow_id])
            del self.__flow_list[flow_id]
        except KeyError:
            pass

        if not by_timer:
            self.__flow_timers[flow_id].cancel()
            del self.__flow_timers[flow_id]

    def add_flow(self, flow):
        self.__flow_list[flow.get_flow_id()] = flow

    def put_in_send_list(self, flow):
        try:
            if self.__send_list.empty():
                self.__send_list.put({
                    flow.get_flow_id(): flow.to_dict_format()
                })
            else:
                flows = self.__send_list.get()
                flows[flow.get_flow_id()] = flow.to_dict_format()
                self.__send_list.put(flows)
        except OSError:
            pass

    def put_in_remove_list(self, flow):
        try:
            if self.__remove_list.empty():
                self.__remove_list.put({
                    flow.get_flow_id(): flow.to_dict_format()
                })
            else:
                flows = self.__remove_list.get()

                flows[flow.get_flow_id()] = flow.to_dict_format()
                self.__remove_list.put(flows)
        except OSError:
            pass

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

            l3_protocol = flowlib.Packet.get_l3_protocol(packet)
            l4_protocol = None

            if "ARP" in l3_protocol[0]:
                pkt = flowlib.ARPPacket(packet)
            else:
                l4_protocol = flowlib.Packet.get_l4_protocol(packet)

                if "ICMP" in l4_protocol[0]:
                    pkt = flowlib.ICMPPacket(packet=packet)
                else:
                    pkt = flowlib.IPPacket(packet=packet)

            for flow in self.__flow_list.values():
                if flow.aggregate(pkt):
                    self.put_in_send_list(flow)
                    aggregation = True

                    if isinstance(flow, flowlib.ARPFlow):
                        if flow.has_request_reply():
                            self.__close_flow(flow_id=flow.get_flow_id(), by_timer=False)
                    break

            try:
                if aggregation is not True:
                    if isinstance(pkt, flowlib.ARPPacket):
                        flow = flowlib.ARPFlow(self.__next_id, pkt.get_source_mac(), pkt.get_source_ip(), pkt.
                                               get_destination_ip())
                        aggregation = flow.aggregate(pkt)
                    else:
                        if 'TCP' in l4_protocol[0]:
                            flow = flowlib.TCPFlow(self.__next_id, pkt.get_source_ip(), pkt.get_destination_ip(), pkt.
                                                   get_source_port(), pkt.get_destination_port(), int(l4_protocol[1]))
                            aggregation = flow.aggregate(pkt,
                                                         counters=self.counter_calculation(packet.ip.src, packet.ip.dst,
                                                                                           int(packet[
                                                                                                   l4_protocol[
                                                                                                       0]].srcport),
                                                                                           int(packet[l4_protocol[
                                                                                               0]].dstport)))
                        elif 'ICMP' in l4_protocol[0]:
                            flow = flowlib.ICMPFlow(self.__next_id, pkt.get_source_ip(), pkt.get_destination_ip(), int(
                                                    l4_protocol[1]))
                            aggregation = flow.aggregate(pkt,
                                                         counters=self.counter_calculation(packet.ip.src, packet.ip.dst,
                                                                                           0, 0))
                        else:
                            flow = flowlib.IPFlow(self.__next_id, pkt.get_source_ip(), pkt.get_destination_ip(), pkt.
                                                  get_source_port(), pkt.get_destination_port(), int(l4_protocol[1]))

                            aggregation = flow.aggregate(pkt,
                                                         counters=self.counter_calculation(packet.ip.src, packet.ip.dst,
                                                                                           int(packet[
                                                                                                   l4_protocol[0]].srcport),
                                                                                           int(packet[l4_protocol[
                                                                                               0]].dstport)))

                    if aggregation:
                        self.add_flow(flow)
                        self.__number_of_flow += 1
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

        self.__sending_service.join(5)
        self.__send_list.close()
        print("[-] Sending service stopped")

        self.__deletion_service.join(5)
        self.__remove_list.close()
        self.__last_ids_removed.close()
        print("[-] Deletion service stopped")

        print("\nNumber of flow recorded :\n\t" + str(self.__number_of_flow))
