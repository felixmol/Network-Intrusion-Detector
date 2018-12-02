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

from queue import Queue
import socketserver
import json
# import deepanalyser


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
    if address in authorized_addresses:
        return True

    return False


def pre_process_data(data, queue):
    try:
        queue.put(json.dumps(data, ensure_ascii=True) + "\n")
    except Exception as e:
        print(str(e))


class CollectorStreamHandler(socketserver.StreamRequestHandler):

    def handle(self):
        print("[+] Connection from " + str(self.client_address))
        if not is_authorized_address(self.client_address[0]):
            print(self.client_address[0] + " is not an authorized extractor.")
            print("[-] Connection closed by " + str(self.server) + "\n")
        else:
            with self.rfile as file:
                data = json.loads(file.read().strip(), encoding="utf-8")
            try:
                for rec in data.keys():
                    print("--- record %i from %s ---" % (data[rec]["flowId"], str(self.client_address)))
                    for key in data[rec].keys():
                        print("\t" + key + " => " + str(data[rec][key]))
                    pre_process_data(data[rec], queue=flow_queue)
            except Exception as e:
                print(str(e))
                pass
            finally:
                print("[-] Connection closed by " + str(self.client_address) + "\n")


if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description='Network feature extractor for RaspberryPi')
    # parser.add_argument("-a", "--server-address", dest="server_address", required=True, type=str, help="Address of the
    # extractor")
    # parser.add_argument("-p", "--server-port", dest="server_port", required=True, type=int, help="Listening port of
    # the collector")
    # args = parser.parse_args(sys.argv)

    authorized_addresses = ["127.0.0.1"]
    deep_analysis_service_use = False

    flow_queue = Queue()

    deep_analyser = None
    # if deep_analysis_service_use:
        # deep_analyser = deepanalyser.DeepAnalyser(flow_queue)
        # deep_analyser.start()

    sock_server = socketserver.TCPServer(("", 8888), CollectorStreamHandler)
    try:
        print("Server listens on " + str(sock_server.server_address[0]) + ":" + str(sock_server.server_address[1]))
        sock_server.serve_forever()
    except KeyboardInterrupt:
        # if deep_analyser is not None:
        #    deep_analyser.join(10)
        while not flow_queue.empty():
            flow_queue.get()
            flow_queue.task_done()
        try:
            flow_queue.join()
        except Exception:
            pass
        print("\nServer closed")
