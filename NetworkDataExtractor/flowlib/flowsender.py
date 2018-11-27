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


import socket
import json
from time import sleep
from multiprocessing import Process


class SendingFlowsException(Exception):
    pass


class InvalidIPv4(Exception):
    pass


def check_ipv4_address(address) -> bool:
    try:
        if len(address.split(".")) == 4:
            for elem in address.split("."):
                if int(elem) < 0 or int(elem) > 255:
                    return False
            return True
        else:
            return False
    except Exception as e:
        raise InvalidIPv4("Invalid IPv4 address: " + str(e))


def send_data(address, port, flows):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as flow_socket:
        try:
            flow_socket.connect((address, port))
            flow_socket.sendall(bytes(json.dumps(flows, ensure_ascii=True), encoding="utf-8"))
        except Exception as e:
            raise SendingFlowsException(str(e))


class FlowSender(Process):

    def __init__(self, address: str, port: int, interval: int, data):
        super().__init__(name="Flow sending process")

        self.__address = address if check_ipv4_address(address) else "127.0.0.1"
        self.__port = port
        self.__interval = interval
        self.__data = data

    def run(self):
        while 1:
            try:
                sleep(self.__interval)
                if len(self.__data.keys()) != 0:
                    try:
                        send_data(address=self.__address, port=self.__port, flows=self.__data.copy())
                        self.__data.clear()
                    except SendingFlowsException as ex:
                        print(str(ex))
                        pass
            except (Exception, KeyboardInterrupt):
                break
