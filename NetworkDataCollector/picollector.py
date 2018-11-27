# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# collector Copyright(c) 2018 Félix Molina.
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

import socketserver
import json


class InvalidIPv4(Exception):
    pass


class ConnectionRefused(Exception):
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


def is_authorized_address(address):
    global authorized_addresses

    if address in authorized_addresses:
        return True

    return False


class CollectorStreamHandler(socketserver.StreamRequestHandler):

    def handle(self):
        print("[+] Connection from " + str(self.client_address))
        if not is_authorized_address(self.client_address[0]):
            print(self.client_address[0] + " is not an authorized extractor.")
        else:
            data = {}
            with self.rfile as file:
                data = json.loads(file.read().strip(), encoding="utf-8")
            for rec in data.keys():
                print("--- record %i from %s ---" % (data[rec]["flowId"], str(self.client_address)))
                for key in data[rec].keys():
                    print("\t" + key + " => " + str(data[rec][key]))
            print("[-] Connection closed by " + str(self.client_address) + "\n")


if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description='Network feature extractor for RaspberryPi')
    # parser.add_argument("-a", "--server-address", dest="server_address", required=True, type=str, help="Address of the
    # extractor")
    # parser.add_argument("-p", "--server-port", dest="server_port", required=True, type=int, help="Listening port of
    # the collector")
    # args = parser.parse_args(sys.argv)

    authorized_addresses = ["127.0.0.1"]
    sock_server = socketserver.TCPServer(("", 8888), CollectorStreamHandler)

    print("Server listens on " + str(sock_server.server_address[0]) + ":" + str(sock_server.server_address[1]))
    try:
        sock_server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer closed")
