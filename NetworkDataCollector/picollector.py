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

from idsconfigparser import SettingParser
from flowsaver import FlowSaver
# from flowanalyser import FlowAnalyser, FlowAnalyserInitError
import multiprocessing
import socketserver
import json
# import argparse
# import sys


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
    if address in authorized_addresses or authorized_addresses is []:
        return True

    return False


def pre_process_data(data: dict):
    try:
        flow_queue.put(data, timeout=2)
        saving_queue.put(data, timeout=2)
    except Exception as e:
        print(str(e))


class CollectorStreamHandler(socketserver.StreamRequestHandler):

    def handle(self):
        print("[+] Connection from " + str(self.client_address))
        if not is_authorized_address(self.client_address[0]):
            print(self.client_address[0] + " is not an authorized extractor.")
            print("[-] Connection closed by " + str(self.server) + "\n")
        else:
            try:
                _data = {}
                with self.rfile as file:
                    data = json.loads(file.read().strip(), encoding="utf-8")

                for rec in data.keys():
                    print("--- record %s from %s ---" % (rec, str(self.client_address)))
                    for key in data[rec].keys():
                        if features_list == [] or key.lower() in features_list:
                            _data[key.lower()] = data[rec][key]
                            print("\t" + key + " => " + str(data[rec][key]))
                    # print(_data)
                    pre_process_data(_data)
            except Exception as e:
                print(str(e))
            finally:
                print("[-] Connection closed by " + str(self.client_address) + "\n")


if __name__ == '__main__':
    # parser = argparse.ArgumentParser(description='Network feature extractor for RaspberryPi')
    # parser.add_argument("-c", "--config", dest="config", required=False, type=str, help="Config file path\nThis must "
    #                                                                                   "be an absolute path otherwise "
    #                                                                                   "config cannot be loaded")
    # args = parser.parse_args(sys.argv)
    conf = "ids_collector.conf"

    # if args.config is not None and args.config != "":
    #    conf = args.config

    deep_analyser = None
    flow_saver = None

    flow_queue = multiprocessing.Queue()
    saving_queue = multiprocessing.Queue()

    setting_parser = SettingParser(filename=conf)
    print("Config parser error : " + setting_parser.error)

    active_debug = setting_parser.get_bool_value("COLLECTOR", "Debug", False)

    authorized_addresses = setting_parser.get_list_value("COLLECTOR", "IpAddresses")
    listening_port = setting_parser.get_int_value("COLLECTOR", "ListeningPort", 8888)

    features_list = setting_parser.get_list_value("COLLECTOR", "Features")

    flow_saving_service = setting_parser.get_bool_value("COLLECTOR", "FlowSavingService", True)
    flow_saver_path = ""
    flow_saver_filename = ""
    flow_saver_limit_size = "10M"
    flow_saver_file_type = "csv"

    if flow_saving_service:
        flow_saver_directory_path = setting_parser.get_str_value("COLLECTOR", "FlowSaverDirectoryPath", "")

        if flow_saver_directory_path == "":
            flow_saving_service = False
        else:
            flow_saver_filename = setting_parser.get_str_value("COLLECTOR", "FlowSaverFilename", "")

            if flow_saver_filename == "":
                flow_saving_service = False

            else:
                flow_saver_limit_size = setting_parser.get_str_value("COLLECTOR", "FileSizeLimit", "100M")
                flow_saver_file_type = setting_parser.get_str_value("COLLECTOR", "FileType", "csv")

                flow_saver = FlowSaver(directory_path=flow_saver_directory_path,
                                       filename=flow_saver_filename,
                                       file_size_limit=flow_saver_limit_size,
                                       queue=saving_queue,
                                       file_type=flow_saver_file_type)
                flow_saver.start()
                print("[+] Flow saving service started")

    deep_analysis_service_use = setting_parser.get_bool_value("COLLECTOR", "DeepAnalysisService", False)

    if deep_analysis_service_use:
        deep_analysis_config_file = setting_parser.get_str_value("COLLECTOR", "DeepAnalyserConfigPath", "")

        if deep_analysis_config_file != "":
            try:
                # deep_analyser = FlowAnalyser(config_path_file=deep_analysis_config_file, queue=flow_queue)
                # deep_analyser.start()
                deep_analyser = None
                print("[+] Flow analysis service started")
            except Exception as e:  # FlowAnalyserInitError as e:
                print(str(e))
                deep_analysis_service_use = False

    sock_server = socketserver.TCPServer(("127.0.0.1", listening_port), CollectorStreamHandler)

    try:
        print("Server listens on " + str(sock_server.server_address[0]) + ":" + str(sock_server.server_address[1]))
        sock_server.serve_forever()
    except KeyboardInterrupt:
        sock_server.shutdown()
        sock_server.server_close()

        if deep_analysis_service_use and deep_analyser is not None:
            deep_analyser.terminate()
            deep_analyser.join(5)
            print("[-] Flow analysis service stopped")

        if flow_saving_service and flow_saver is not None:
            # flow_saver.terminate()
            flow_saver.join()
            print("[-] Flow saving service stopped")

        flow_queue.close()
        flow_queue.join_thread()

        saving_queue.close()
        saving_queue.join_thread()

        print("\nServer closed")
