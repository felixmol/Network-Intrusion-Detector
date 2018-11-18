# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# data sender Copyright(c) 2018 Félix Molina.
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


from multiprocessing import Process

import socket


def send_data(address: str, port: int, data: list):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((address, port))
        for flow in data:
            sock.sendall(bytes(flow))


class InitDataSenderException(Exception):
    pass


class DataSender(Process):

    def __init__(self, group: object = None, target: function = send_data, name: str = None, args: tuple =
                    ("127.0.0.1", 4957, [],), kwargs: dict = None, address: str = "127.0.0.1", port: int = 4957,
                    interval: int = 0):
        super().__init__(group=group, target=target, name=name, args=args, kwargs=kwargs if kwargs is not None else {})
        try:
            if self.check_ipv4_address(address):
                self.address = address
            else:
                raise InitDataSenderException("Invalid server address")
            self.port = port if isinstance(port, int) else int(port)
            self.interval = interval if isinstance(interval, int) else int(interval)
        except Exception as e:
            raise InitDataSenderException(e)

    @staticmethod
    def check_ipv4_address(address) -> bool:
        if len(address.split(".")) == 4:
            for elem in address.split("."):
                if int(elem) < 0 or int(elem) > 255:
                    return False
            return True
        else:
            return False
