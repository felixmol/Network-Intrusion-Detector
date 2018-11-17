# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# packet (c) 2018 Félix Molina.
#
# Many thanks to Télécom SudParis (http://www.telecom-sudparis.eu) for
# its material support of this effort.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#

from flowlib.consts import FLAGS


class PacketInitException(Exception):
    pass


class Packet(object):
    def __init__(self, packet):
        try:
            self.source_ip = packet.ip.src
            self.destination_ip = packet.ip.dst
            self.source_port = int(packet[self.get_protocol(packet)[0]].srcport)
            self.destination_port = int(packet[self.get_protocol(packet)[0]].dstport)
            self.transport_protocol = int(self.get_protocol(packet)[1])
            # self.app_protocol = app_protocol
            self.size = int(packet.length)
            self.flags = self.__get_flags(packet)
            self.ttl = int(packet.ip.ttl)
            self.hash = self.__hash()
        except Exception as e:
            raise PacketInitException(e)

    def __hash(self):
        string1 = self.source_ip + self.destination_ip + str(self.source_port) \
                  + str(self.destination_port) + str(self.transport_protocol)
        return hash(string1)

    @staticmethod
    def __get_flags(packet):
        flags = []
        try:
            for flag in FLAGS.keys():
                if int(packet.tcp.get_field_value(FLAGS[flag])) == 1:
                    flags += [flag]
            return flags
        except:
            return []

    @staticmethod
    def get_protocol(packet) -> list:
        """

        :param packet:
        :rtype: list
        :return:
        """
        return packet.ip.proto.showname_value.replace('(', '').replace(')', '').split(' ')

    def get_length(self) -> int:
        """
        Public method.
        This method return the size of the packet object in bytes.
        :rtype: int
        :return: The size of the packet in bytes.
        """
        return self.size

    def get_ttl(self):
        return self.ttl

    def get_flags(self):
        return self.flags

    def get_hash(self):
        return self.hash
