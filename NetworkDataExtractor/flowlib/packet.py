# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# packet Copyright(c) 2018 Félix Molina.
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

from flowlib.consts import FLAGS


class PacketInitException(Exception):
    pass


class __Packet(object):

    def __init__(self, packet):
        super().__init__()


class Packet(__Packet):

    def __init__(self, packet):
        super().__init__(packet=packet)

    @staticmethod
    def get_l3_protocol(packet) -> list:
        """

        :param packet:
        :rtype: list
        :return:
        """
        return packet.eth.type.showname_value.replace('(', '').replace(')', '').split(' ')

    @staticmethod
    def get_l4_protocol(packet) -> list:
        """

        :param packet:
        :rtype: list
        :return:
        """
        return packet.ip.proto.showname_value.replace('(', '').replace(')', '').split(' ')

    def __hash(self):
        pass

    def get_length(self) -> int:
        """
        Public method.
        This method return the size of the packet object in bytes.
        :rtype: int
        :return: The size of the packet in bytes.
        """
        pass

    def get_hash(self):
        pass


class ARPPacket(Packet):

    def __init__(self, packet):
        super().__init__(packet=packet)

        try:
            self.__source_mac = packet.arp.src_hw_mac
            self.__destination_mac = packet.arp.dst_hw_mac
            self.__source_ip = packet.arp.src_proto_ipv4
            self.__destination_ip = packet.arp.dst_proto_ipv4
            self.__size = int(packet.length)
            self.__hash = self.__hash()

            if "request" in packet.arp.opcode.showname_value.split(" ")[0]:
                self.__reply = True
                self.__request = False
            elif "reply" in packet.arp.opcode.showname_value.split(" ")[0]:
                self.__request = True
                self.__reply = False
        except Exception as e:
            raise PacketInitException(str(e))

    def __hash(self):
        string1 = self.__source_ip + self.__destination_ip
        return hash(string1)

    def get_length(self) -> int:
        """
        Public method.
        This method return the size of the packet object in bytes.
        :rtype: int
        :return: The size of the packet in bytes.
        """
        return self.__size

    def get_source_mac(self):
        return self.__source_mac

    def get_source_ip(self):
        return self.__source_ip

    def get_destination_ip(self):
        return self.__destination_ip

    def get_destination_mac(self):
        return self.__destination_mac

    def is_request(self):
        return self.__request

    def is_reply(self):
        return self.__reply

    def get_hash(self):
        return self.__hash


class ICMPPacket(Packet):

    def __init__(self, packet):
        super().__init__(packet=packet)
        try:
            self._source_mac = packet.eth.src_resolved
            self._destination_mac = packet.eth.dst_resolved
            self._source_ip = packet.ip.src
            self._destination_ip = packet.ip.dst
            self._transport_protocol = int(self.get_l4_protocol(packet)[1])
            self._size = int(packet.length)
            self._ttl = int(packet.ip.ttl)
            self._hash = self.__hash()
        except Exception as e:
            raise PacketInitException(str(e))

    def __hash(self):
        string1 = self._source_ip + self._destination_ip + str(self._transport_protocol)
        return hash(string1)

    def get_length(self) -> int:
        """
        Public method.
        This method return the size of the packet object in bytes.
        :rtype: int
        :return: The size of the packet in bytes.
        """
        return self._size

    def get_source_mac(self):
        return self._source_mac

    def get_source_ip(self):
        return self._source_ip

    def get_destination_ip(self):
        return self._destination_ip

    def get_destination_mac(self):
        return self._destination_mac

    def get_ttl(self):
        return self._ttl

    def get_hash(self):
        return self._hash


class IPPacket(ICMPPacket):

    def __init__(self, packet):
        super().__init__(packet=packet)
        try:
            self._source_port = int(packet[self.get_l4_protocol(packet)[0]].srcport)
            self._destination_port = int(packet[self.get_l4_protocol(packet)[0]].dstport)
            self._flags = self._get_flags(packet)
            self._ttl = int(packet.ip.ttl)
            self._hash = self.__hash()
        except Exception as e:
            raise PacketInitException(str(e))

    def __hash(self):
        string1 = self._source_ip + self._destination_ip + str(self._source_port) \
                  + str(self._destination_port) + str(self._transport_protocol)
        return hash(string1)

    @staticmethod
    def _get_flags(packet):
        flags = []
        try:
            for flag in FLAGS.keys():
                if int(packet.tcp.get_field_value(FLAGS[flag])) == 1:
                    flags += [flag]
            return flags
        except:
            return []

    def get_source_port(self):
        return self._source_port

    def get_destination_port(self):
        return self._destination_port

    def get_flags(self):
        return self._flags
