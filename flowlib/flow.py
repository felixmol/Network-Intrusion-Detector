# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# flow (c) 2018 Félix Molina.
#
# Many thanks to Télécom SudParis (http://www.telecom-sudparis.eu) for
# its material support of this effort.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#

from flowlib.consts import Direction
from flowlib.consts import Flag
from flowlib.consts import ConnectionState
from flowlib.packet import Packet

from flowlib.consts import CONNECTION_FLAGS

import datetime


class Flow(object):

    def __init__(self, source_ip: str, destination_ip: str, source_port: int, destination_port: int,
                 transport_protocol: int, app_protocol: int = None):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.source_port = source_port
        self.destination_port = destination_port
        self.transport_protocol = transport_protocol
        self.app_protocol = app_protocol

        self.flow_start_time = datetime.datetime.now()
        self.flow_end_time = 0
        self.flow_duration_microseconds = 0
        self.last_received_packet_time = datetime.datetime.now()
        self.delta_time_between_packets = []

        self.min_size = 0
        self.max_size = 0
        self.delta_size_bytes = 0
        self.sum_size_bytes = 0

        self.min_ttl = 0
        self.max_ttl = 0

        self.direction = Direction.SourceToDestination
        self.packet_list = []

        self.hash_src_to_dst, self.hash_dst_to_src = self.__hash()

        self.closed = False

    def __compare(self, packet_hash):

        if packet_hash == self.hash_src_to_dst:
            return 1
        elif packet_hash == self.hash_dst_to_src:
            return 2
        else:
            return 0

    def __size_actualisation(self, size):
        self.min_size = self.min_size if size >= self.min_size else size
        self.max_size = self.max_size if size <= self.max_size else size
        self.delta_size_bytes = self.max_size - self.min_size
        self.sum_size_bytes += size

    def __ttl_actualisation(self, ttl):
        self.min_ttl = self.min_ttl if ttl >= self.min_ttl else ttl
        self.max_ttl = self.max_ttl if ttl <= self.max_ttl else ttl

    def __flow_duration(self) -> None:
        """
        Private method.
        Achieve calculation of the flow duration.
        :rtype: None
        """
        self.flow_end_time = datetime.datetime.now()
        self.flow_duration_microseconds = (self.flow_end_time - self.flow_start_time).microseconds

    def __add_packet(self, packet: Packet) -> None:
        """
        Private method.
        Use to append a new packet in the packet list of the flow object.
        :rtype: None
        :param packet: flowlib.packet.Packet
        """
        self.packet_list += [packet]

    def __hash(self) -> (int, int):
        """
        Private personalized hashing method.
        It hashs the source and the destination IP and port, and the transport protocol number.
        :rtype: (int, int)
        :return: 2-tuple - hash of the Source to Destination direction, hash of the Destination to Source.
        """
        string1 = self.source_ip + self.destination_ip + str(self.source_port) + str(self.destination_port) + str(
            self.transport_protocol)
        string2 = self.destination_ip + self.source_ip + str(self.destination_port) + str(self.source_port) + str(
            self.transport_protocol)

        return hash(string1), hash(string2)

    def aggregate(self, packet):
        if self.__compare(packet.get_hash()) == 2:
            self.direction = Direction.BiDirectional
        elif self.__compare(packet.get_hash()) == 0:
            return False

        self.__add_packet(packet)
        self.__size_actualisation(packet.get_length())
        self.__ttl_actualisation(packet.ip.ttl)
        self.__flow_duration()

        if self.packet_list:
            self.delta_time_between_packets += [datetime.datetime.now() - self.last_received_packet_time]
            self.last_received_packet_time = datetime.datetime.now()

        return True

    def is_closed(self):
        return self.closed

    def packet_direction(self, packet):
        if self.__compare(packet.get_hash()) == 1:
            return Direction.SourceToDestination
        elif self.__compare(packet.get_hash()) == 2:
            return Direction.DestinationToSource


class TCPFlow(Flow):

    def __init__(self, source_ip: str, destination_ip: str, source_port: int, destination_port: int,
                 transport_protocol: int, app_protocol: int = None):
        super().__init__(source_ip, destination_ip, source_port, destination_port, transport_protocol, app_protocol)

        self.flags = CONNECTION_FLAGS
        self.open = False

    def __follow_flag_flow(self, packet):
        direction = self.packet_direction(packet)
        for flag in packet.get_flags():
            if flag == Flag.SYN:
                if direction == Direction.SourceToDestination:
                    self.flags[ConnectionState.ESTABLISHMENT][ConnectionState.SYN_SRC] = 1
                else:
                    self.flags[ConnectionState.ESTABLISHMENT][ConnectionState.SYN_DST] = 1
            elif flag == Flag.FIN:
                if direction == Direction.SourceToDestination:
                    self.flags[ConnectionState.TERMINATION][ConnectionState.FIN_SRC] = 1
                else:
                    self.flags[ConnectionState.TERMINATION][ConnectionState.FIN_DST] = 1
            elif flag == Flag.ACK:
                if self.flags[ConnectionState.ESTABLISHMENT][ConnectionState.SYN_DST] == 1 and \
                        direction == Direction.SourceToDestination and \
                        (self.flags[ConnectionState.TERMINATION][ConnectionState.FIN_SRC] == 0 and
                         self.flags[ConnectionState.TERMINATION][ConnectionState.FIN_DST] == 0):
                    self.flags[ConnectionState.ESTABLISHMENT][ConnectionState.ACK_SRC] = 1
                elif self.flags[ConnectionState.ESTABLISHMENT][ConnectionState.SYN_SRC] == 1 and \
                        direction == Direction.DestinationToSource and \
                        (self.flags[ConnectionState.TERMINATION][ConnectionState.FIN_SRC] == 0 and
                         self.flags[ConnectionState.TERMINATION][ConnectionState.FIN_DST] == 0):
                    self.flags[ConnectionState.ESTABLISHMENT][ConnectionState.ACK_DST] = 1
                elif self.flags[ConnectionState.TERMINATION][ConnectionState.FIN_DST] == 1 and \
                        direction == Direction.SourceToDestination and \
                        (self.flags[ConnectionState.ESTABLISHMENT][ConnectionState.SYN_SRC] == 1 and
                         self.flags[ConnectionState.TERMINATION][ConnectionState.SYN_DST] == 1):
                    self.flags[ConnectionState.TERMINATION][ConnectionState.ACK_SRC] = 1
                elif self.flags[ConnectionState.TERMINATION][ConnectionState.FIN_SRC] == 1 and \
                        direction == Direction.DestinationToSource and \
                        (self.flags[ConnectionState.ESTABLISHMENT][ConnectionState.SYN_SRC] == 1 and
                         self.flags[ConnectionState.ESTABLISHMENT][ConnectionState.SYN_DST] == 1):
                    self.flags[ConnectionState.TERMINATION][ConnectionState.ACK_DST] = 1
                else:
                    pass

    def aggregate(self, packet):
        if super().aggregate(packet):
            self.__follow_flag_flow(packet)
            self.connection_state()
            return True
        return False

    def is_open(self):
        return self.open

    def connection_state(self):
        if 0 not in self.flags[ConnectionState.ESTABLISHMENT].values():
            self.open = True

        if 0 not in self.flags[ConnectionState.TERMINATION].values():
            self.open = False
            self.closed = True

        return {'open': self.open, 'closed': self.closed}
