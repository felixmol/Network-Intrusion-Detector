# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# flow Copyright(c) 2018 Félix Molina.
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

from flowlib.consts import Direction
from flowlib.consts import Flag
from flowlib.consts import ConnectionState

from flowlib.consts import CONNECTION_FLAGS

from flowlib.packet import Packet
from flowlib.packet import ARPPacket
from flowlib.packet import IPPacket

import time
import json


def get_current_milli():
    return int(round(time.time() * 1000))


class FlowInitException(Exception):
    pass


class __Flow(object):

    def __init__(self):
        super().__init__()


class Flow(__Flow):
    def __init__(self, flow_id: int, source_mac: str = None, destination_mac: str = None):
        super().__init__()

        try:
            self._id = flow_id

            self._source_mac = None
            self._destination_mac = None

            if source_mac:
                self._source_mac = source_mac
            if destination_mac:
                self._destination_mac = destination_mac

            self._flow_start_time = get_current_milli()
            self._flow_end_time = 0
            self._flow_duration_milliseconds = 0
            self._last_received_packet_time = get_current_milli()
            self._delta_time_between_packets = []
            self._rate = 0

            self._min_size = 0
            self._max_size = 0
            self._packet_sizes = []
            self._delta_size_bytes = 0
            self._sum_size_bytes = 0

            self._total_packet = 0
            self._packet_list = []

            self._closed = False
        except Exception as e:
            raise FlowInitException(str(e))

    def _size_actualisation(self, size, direction):
        self._min_size = self._min_size if size >= self._min_size and self._packet_list != [] else size
        self._max_size = self._max_size if size <= self._max_size else size
        self._delta_size_bytes = self._max_size - self._min_size

        self._sum_size_bytes += size
        self._packet_sizes += [size]

    def _flow_duration(self) -> None:
        """
        Private method.
        Achieve calculation of the flow duration.
        :rtype: None
        """
        self._flow_end_time = get_current_milli()
        self._flow_duration_milliseconds = self._flow_end_time - self._flow_start_time
        self._rate = self._total_packet / (
            round(self._flow_duration_milliseconds * 1000, 3) if self._flow_duration_milliseconds > 0 else 1)

    def _add_packet(self, packet: Packet) -> None:
        """
        Private method.
        Use to append a new packet in the packet list of the flow object.
        :rtype: None
        :param packet: flowlib.packet.Packet
        """
        self._packet_list += [packet]
        self._total_packet = len(self._packet_list)

    def _hash(self):
        pass

    def close_flow(self):
        self._flow_duration()
        self._closed = True

    def aggregate(self, packet, counters=None):
        if self._closed is not True:
            if len(self._packet_list) != 0:
                self._delta_time_between_packets += [get_current_milli() - self._last_received_packet_time]
                self._last_received_packet_time = get_current_milli()

            self._add_packet(packet)
            self._size_actualisation(packet.get_length(), None)
            self._flow_duration()
            return True

        return False

    def to_dict_format(self):
        pass

    def to_json_format(self):
        pass

    def is_closed(self):
        return self._closed

    def get_flow_id(self):
        return self._id

    def get_start_time(self):
        return self._flow_start_time


class ARPFlow(Flow):
    def __init__(self, flow_id: int, source_mac: str, source_ip: str, destination_ip: str):
        super().__init__(flow_id=flow_id, source_mac=source_mac, destination_mac=None)

        try:
            self._source_ip = source_ip
            self._destination_ip = destination_ip

            self._source_to_destination_size_bytes = 0
            self._destination_to_source_size_bytes = 0
            self._mean_packet_size_from_source = 0
            self._mean_packet_size_from_destination = 0

            self._direction = Direction.SourceToDestination

            self._source_to_destination_packet_number = 0
            self._destination_to_source_packet_number = 0
            self._total_packet = self._source_to_destination_packet_number + self.\
                _destination_to_source_packet_number

            self._request = False
            self._reply = False

            self._hash_src_to_dst, self._hash_dst_to_src = self._hash()
        except Exception as e:
            raise FlowInitException(str(e))

    def _hash(self):
        return hash(self._source_ip + self._destination_ip), hash(self._destination_ip + self._source_ip)

    def _compare(self, packet_hash: int):

        if packet_hash == self._hash_src_to_dst:
            return 1
        elif packet_hash == self._hash_dst_to_src:
            return 2
        else:
            return 0

    def _size_actualisation(self, size: int, direction: Direction):
        super()._size_actualisation(size=size, direction=direction)
        if direction is Direction.SourceToDestination:
            self._source_to_destination_size_bytes += size
        else:
            self._destination_to_source_size_bytes += size

        self._mean_packet_size_from_source = self._source_to_destination_size_bytes / (
            self._source_to_destination_packet_number if self._source_to_destination_packet_number > 0 else 1)
        self._mean_packet_size_from_destination = self._destination_to_source_size_bytes / (
            self._destination_to_source_packet_number if self._destination_to_source_packet_number > 0 else 1)

    def _add_packet(self, packet: ARPPacket) -> None:
        """
        Private method.
        Use to append a new packet in the packet list of the flow object.
        :rtype: None
        :param packet: flowlib.packet.Packet
        """
        super()._add_packet(packet=packet)

        if self._compare(packet.get_hash()) is 1:
            self._source_to_destination_packet_number += 1
        else:
            self._destination_to_source_packet_number += 1

    def to_dict_format(self):
        return {
            "flowId": self._id,
            "sourceMac": self._source_mac,
            "destinationMac": self._destination_mac,
            "sourceIp": self._source_ip,
            "destinationIp": self._destination_ip,
            "request": self._request,
            "reply": self._reply,
            "flowStartTime": self._flow_start_time,
            "flowEndTime": self._flow_end_time,
            "flowDurationMilliseconds": self._flow_duration_milliseconds,
            "deltaTimeBetweenPackets": self._delta_time_between_packets,
            "flowRate": self._rate,
            "minSize": self._min_size,
            "maxSize": self._max_size,
            "packetSizes": self._packet_sizes,
            "deltaSizeBytes": self._delta_size_bytes,
            "sumSizeBytes": self._sum_size_bytes,
            "meanPacketSizeFromSource": self._mean_packet_size_from_source,
            "meanPacketSizeFromDestination": self._mean_packet_size_from_destination,
            "sourceToDestinationSizeBytes": self._source_to_destination_size_bytes,
            "destinationToSourceSizeBytes": self._destination_to_source_size_bytes,
            "sourceToDestinationPacketNumber": self._source_to_destination_packet_number,
            "destinationToSourcePacketNumber": self._destination_to_source_packet_number,
            "totalPacket": self._total_packet,
            "direction": self._direction.value,
            "closed": self._closed
        }

    def to_json_format(self):
        return json.dumps(self.to_dict_format(), ensure_ascii=True)

    def aggregate(self, packet: ARPPacket, counters=None):
        if self._closed is not True:
            if self._compare(packet.get_hash()) == 2:
                self._direction = Direction.BiDirectional
                self._destination_mac = packet.get_source_mac()
            elif self._compare(packet.get_hash()) == 0:
                return False

            if packet.is_request():
                self._request = True
            elif packet.is_reply():
                self._reply = True

            if len(self._packet_list) != 0:
                self._delta_time_between_packets += [get_current_milli() - self._last_received_packet_time]
                self._last_received_packet_time = get_current_milli()

            self._size_actualisation(packet.get_length(), self.packet_direction(packet))
            self._add_packet(packet)
            self._flow_duration()

            return True

        return False

    def packet_direction(self, packet: ARPPacket):
        if self._compare(packet.get_hash()) == 1:
            return Direction.SourceToDestination
        elif self._compare(packet.get_hash()) == 2:
            return Direction.DestinationToSource

    def close_flow(self):
        if self._request and self._reply and self._total_packet % 2 is 0:
            self._flow_duration()
            self._closed = True

    def has_request_reply(self):
        return self._request and self._reply


class ICMPFlow(Flow):

    def __init__(self, flow_id: int, source_mac: str, destination_mac: str, source_ip: str, destination_ip: str,
                 transport_protocol: int):
        super().__init__(flow_id=flow_id, source_mac=source_mac, destination_mac=destination_mac)

        try:
            self._source_ip = source_ip
            self._destination_ip = destination_ip
            self._transport_protocol = transport_protocol

            self._source_to_destination_size_bytes = 0
            self._destination_to_source_size_bytes = 0
            self._mean_packet_size_from_source = 0
            self._mean_packet_size_from_destination = 0

            self._min_ttl = 0
            self._max_ttl = 0
            self._source_to_destination_ttl = 0
            self._destination_to_source_ttl = 0

            self._direction = Direction.SourceToDestination

            self._source_to_destination_packet_number = 0
            self._destination_to_source_packet_number = 0
            self._total_packet = self._source_to_destination_packet_number + self.\
                _destination_to_source_packet_number

            self._count_same_destination_address = 0
            self._count_same_source_destination_address = 0

            self._hash_src_to_dst, self._hash_dst_to_src = self.__hash()
        except Exception as e:
            raise FlowInitException(str(e))

    def _compare(self, packet_hash: int):

        if packet_hash == self._hash_src_to_dst:
            return 1
        elif packet_hash == self._hash_dst_to_src:
            return 2
        else:
            return 0

    def _size_actualisation(self, size: int, direction: Direction):
        super()._size_actualisation(size=size, direction=direction)
        if direction is Direction.SourceToDestination:
            self._source_to_destination_size_bytes += size
        else:
            self._destination_to_source_size_bytes += size

        self._mean_packet_size_from_source = self._source_to_destination_size_bytes / (
            self._source_to_destination_packet_number if self._source_to_destination_packet_number > 0 else 1)
        self._mean_packet_size_from_destination = self._destination_to_source_size_bytes / (
            self._destination_to_source_packet_number if self._destination_to_source_packet_number > 0 else 1)

    def _ttl_actualisation(self, ttl: int, direction: Direction):
        self._min_ttl = self._min_ttl if ttl >= self._min_ttl and self._packet_list != [] else ttl
        self._max_ttl = self._max_ttl if ttl <= self._max_ttl else ttl

        if direction is Direction.SourceToDestination:
            self._source_to_destination_ttl = ttl
        else:
            self._destination_to_source_ttl = ttl

    def _counter_actualisation(self, counters: dict):
        self._count_same_destination_address = counters["ct_dst_ltm"]
        self._count_same_source_destination_address = counters["ct_dst_ltm"]

    def _add_packet(self, packet: IPPacket) -> None:
        """
        Private method.
        Use to append a new packet in the packet list of the flow object.
        :rtype: None
        :param packet: flowlib.packet.Packet
        """
        super()._add_packet(packet=packet)

        if self._compare(packet.get_hash()) is 1:
            self._source_to_destination_packet_number += 1
        else:
            self._destination_to_source_packet_number += 1

    def __hash(self) -> (int, int):
        """
        Private personalized hashing method.
        It hashs the source and the destination IP and port, and the transport protocol number.
        :rtype: (int, int)
        :return: 2-tuple - hash of the Source to Destination direction, hash of the Destination to Source.
        """
        string1 = self._source_ip + self._destination_ip + str(self._transport_protocol)
        string2 = self._destination_ip + self._source_ip + str(self._transport_protocol)

        return hash(string1), hash(string2)

    def to_dict_format(self):
        return {
            "flowId": self._id,
            "sourceIp": self._source_ip,
            "destinationIp": self._destination_ip,
            "transportProtocol": self._transport_protocol,
            "flowStartTime": self._flow_start_time,
            "flowEndTime": self._flow_end_time,
            "flowDurationMilliseconds": self._flow_duration_milliseconds,
            "deltaTimeBetweenPackets": self._delta_time_between_packets,
            "flowRate": self._rate,
            "minSize": self._min_size,
            "maxSize": self._max_size,
            "packetSizes": self._packet_sizes,
            "deltaSizeBytes": self._delta_size_bytes,
            "sumSizeBytes": self._sum_size_bytes,
            "meanPacketSizeFromSource": self._mean_packet_size_from_source,
            "meanPacketSizeFromDestination": self._mean_packet_size_from_destination,
            "sourceToDestinationSizeBytes": self._source_to_destination_size_bytes,
            "destinationToSourceSizeBytes": self._destination_to_source_size_bytes,
            "sourceToDestinationPacketNumber": self._source_to_destination_packet_number,
            "destinationToSourcePacketNumber": self._destination_to_source_packet_number,
            "totalPacket": self._total_packet,
            "minTTL": self._min_ttl,
            "maxTTL": self._max_ttl,
            "sourceToDestinationTTL": self._source_to_destination_ttl,
            "destinationToSourceTTL": self._destination_to_source_ttl,
            "direction": self._direction.value,
            "countSameDestinationAddress": self._count_same_destination_address,
            "countSameSourceDestinationAddress": self._count_same_source_destination_address,
            "closed": self._closed
        }

    def to_json_format(self):
        return json.dumps(self.to_dict_format(), ensure_ascii=True)

    def aggregate(self, packet: IPPacket, counters=None):
        if self._closed is not True:
            if self._compare(packet.get_hash()) == 2:
                self._direction = Direction.BiDirectional
            elif self._compare(packet.get_hash()) == 0:
                return False

            if len(self._packet_list) != 0:
                self._delta_time_between_packets += [get_current_milli() - self._last_received_packet_time]
                self._last_received_packet_time = get_current_milli()

            self._size_actualisation(packet.get_length(), self.packet_direction(packet))
            self._ttl_actualisation(packet.get_ttl(), self.packet_direction(packet))
            self._add_packet(packet)
            self._flow_duration()

            if counters is not None:
                self._counter_actualisation(counters)

            return True

        return False

    def packet_direction(self, packet: IPPacket):
        if self._compare(packet.get_hash()) == 1:
            return Direction.SourceToDestination
        elif self._compare(packet.get_hash()) == 2:
            return Direction.DestinationToSource


class IPFlow(ICMPFlow):

    def __init__(self, flow_id: int, source_mac: str, destination_mac: str, source_ip: str, destination_ip: str,
                 source_port: int, destination_port: int, transport_protocol: int, app_protocol: int = None):
        super().__init__(flow_id=flow_id, source_mac=source_mac, destination_mac=destination_mac, source_ip=source_ip,
                         destination_ip=destination_ip, transport_protocol=transport_protocol)

        try:
            self._source_port = source_port
            self._destination_port = destination_port
            self._app_protocol = app_protocol

            self._count_same_source_address_destination_port = 0
            self._count_same_destination_address_source_port = 0

            self._hash_src_to_dst, self._hash_dst_to_src = self.__hash()
        except Exception as e:
            print(str(e))
            raise FlowInitException(str(e))

    def _counter_actualisation(self, counters: dict):
        self._count_same_destination_address = counters["ct_dst_ltm"]
        self._count_same_source_address_destination_port = counters["ct_dst_ltm"]
        self._count_same_destination_address_source_port = counters["ct_dst_ltm"]
        self._count_same_source_destination_address = counters["ct_dst_ltm"]

    def __hash(self) -> (int, int):
        """
        Private personalized hashing method.
        It hashs the source and the destination IP and port, and the transport protocol number.
        :rtype: (int, int)
        :return: 2-tuple - hash of the Source to Destination direction, hash of the Destination to Source.
        """
        string1 = self._source_ip + self._destination_ip + str(self._source_port) + str(
            self._destination_port) + str(self._transport_protocol)
        string2 = self._destination_ip + self._source_ip + str(self._destination_port) + str(
            self._source_port) + str(self._transport_protocol)

        return hash(string1), hash(string2)

    def to_dict_format(self):
        return {
            "flowId": self._id,
            "sourceIp": self._source_ip,
            "destinationIp": self._destination_ip,
            "sourcePort": self._source_port,
            "destinationPort": self._destination_port,
            "transportProtocol": self._transport_protocol,
            "flowStartTime": self._flow_start_time,
            "flowEndTime": self._flow_end_time,
            "flowDurationMilliseconds": self._flow_duration_milliseconds,
            "deltaTimeBetweenPackets": self._delta_time_between_packets,
            "flowRate": self._rate,
            "minSize": self._min_size,
            "maxSize": self._max_size,
            "packetSizes": self._packet_sizes,
            "deltaSizeBytes": self._delta_size_bytes,
            "sumSizeBytes": self._sum_size_bytes,
            "meanPacketSizeFromSource": self._mean_packet_size_from_source,
            "meanPacketSizeFromDestination": self._mean_packet_size_from_destination,
            "sourceToDestinationSizeBytes": self._source_to_destination_size_bytes,
            "destinationToSourceSizeBytes": self._destination_to_source_size_bytes,
            "sourceToDestinationPacketNumber": self._source_to_destination_packet_number,
            "destinationToSourcePacketNumber": self._destination_to_source_packet_number,
            "totalPacket": self._total_packet,
            "minTTL": self._min_ttl,
            "maxTTL": self._max_ttl,
            "sourceToDestinationTTL": self._source_to_destination_ttl,
            "destinationToSourceTTL": self._destination_to_source_ttl,
            "direction": self._direction.value,
            "countSameDestinationAddress": self._count_same_destination_address,
            "countSameSourceAddressDestinationPort": self._count_same_source_address_destination_port,
            "countSameDestinationAddressSourcePort": self._count_same_destination_address_source_port,
            "countSameSourceDestinationAddress": self._count_same_source_destination_address,
            "closed": self._closed
        }


class TCPFlow(IPFlow):
    def __init__(self, flow_id: int, source_mac: str, destination_mac: str, source_ip: str, destination_ip: str,
                 source_port: int, destination_port: int, transport_protocol: int, app_protocol: int = None):
        super().__init__(flow_id=flow_id, source_mac=source_mac, destination_mac=destination_mac, source_ip=source_ip,
                         destination_ip=destination_ip, source_port=source_port, destination_port=destination_port,
                         transport_protocol=transport_protocol, app_protocol=app_protocol)

        self._flags = CONNECTION_FLAGS
        self._open = False

    def _follow_flag_flow(self, packet: IPPacket):
        direction = self.packet_direction(packet)
        for flag in packet.get_flags():
            if flag == Flag.SYN:
                if direction == Direction.SourceToDestination:
                    self._flags[ConnectionState.ESTABLISHMENT][ConnectionState.SYN_SRC] = 1
                else:
                    self._flags[ConnectionState.ESTABLISHMENT][ConnectionState.SYN_DST] = 1
            elif flag == Flag.FIN:
                if direction == Direction.SourceToDestination:
                    self._flags[ConnectionState.TERMINATION][ConnectionState.FIN_SRC] = 1
                else:
                    self._flags[ConnectionState.TERMINATION][ConnectionState.FIN_DST] = 1
            elif flag == Flag.ACK:
                if self._flags[ConnectionState.ESTABLISHMENT][
                    ConnectionState.SYN_DST] == 1 and direction == Direction.SourceToDestination and (
                                self._flags[ConnectionState.TERMINATION][ConnectionState.FIN_SRC] == 0 and
                                self._flags[ConnectionState.TERMINATION][ConnectionState.FIN_DST] == 0):
                    self._flags[ConnectionState.ESTABLISHMENT][ConnectionState.ACK_SRC] = 1
                elif self._flags[ConnectionState.ESTABLISHMENT][
                    ConnectionState.SYN_SRC] == 1 and direction == Direction.DestinationToSource and (
                                self._flags[ConnectionState.TERMINATION][ConnectionState.FIN_SRC] == 0 and
                                self._flags[ConnectionState.TERMINATION][ConnectionState.FIN_DST] == 0):
                    self._flags[ConnectionState.ESTABLISHMENT][ConnectionState.ACK_DST] = 1
                elif self._flags[ConnectionState.TERMINATION][
                    ConnectionState.FIN_DST] == 1 and direction == Direction.SourceToDestination and (
                                self._flags[ConnectionState.ESTABLISHMENT][ConnectionState.SYN_SRC] == 1 and
                                self._flags[ConnectionState.TERMINATION][ConnectionState.SYN_DST] == 1):
                    self._flags[ConnectionState.TERMINATION][ConnectionState.ACK_SRC] = 1
                elif self._flags[ConnectionState.TERMINATION][
                    ConnectionState.FIN_SRC] == 1 and direction == Direction.DestinationToSource and (
                                self._flags[ConnectionState.ESTABLISHMENT][ConnectionState.SYN_SRC] == 1 and
                                self._flags[ConnectionState.ESTABLISHMENT][ConnectionState.SYN_DST] == 1):
                    self._flags[ConnectionState.TERMINATION][ConnectionState.ACK_DST] = 1
                else:
                    pass

                    #    def aggregate(self, packet):
                    #        if super().aggregate(packet):
                    #            self._follow_flag_flow(packet)
                    #            self.connection_state()
                    #
                    #            return True
                    #
                    #        return False

    def is_open(self):
        return self._open

    def connection_state(self):
        if 0 not in self._flags[ConnectionState.ESTABLISHMENT].values():
            self._open = True

        if 0 not in self._flags[ConnectionState.TERMINATION].values():
            self._open = False
            self.close_flow()

        return {'open': self.is_open(), 'closed': self.is_closed()}
