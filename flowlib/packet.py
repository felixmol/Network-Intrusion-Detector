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
