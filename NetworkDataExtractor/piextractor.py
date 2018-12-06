# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# extractor Copyright(c) 2018 Félix Molina.
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

from datetime import datetime
from idsconfigparser import SettingParser
import pyshark
import flowlib
import argparse
import sys
import json


def main(config_filename: str):
    setting_parser = SettingParser(filename=config_filename)
    print("Config parser error : " + setting_parser.error)

    interface = setting_parser.get_str_value("EXTRACTOR", "Interface", "")

    output_file = setting_parser.get_str_value("EXTRACTOR", "OutputFilePath", "") if setting_parser.get_bool_value(
        "EXTRACTOR", "OutputFile", False) else None
    if output_file == "":
        output_file = None

    capture_filters = setting_parser.get_str_value("EXTRACTOR", "CaptureFilters", "")
    if capture_filters == "":
        capture_filters = None

    active_debug = setting_parser.get_bool_value("EXTRACTOR", "Debug", False)

    flow_manager = flowlib.FlowManager(setting_parser)
    flow_manager.start_service()

    start_time = datetime.now()

    capture = pyshark.LiveCapture(interface=interface, output_file=output_file, capture_filter=capture_filters)
    capture.set_debug(active_debug)

    try:
        capture.apply_on_packets(flow_manager.packet_analysis)
    except (Exception, KeyboardInterrupt) as e:
        print(e)
        pass
    finally:
        end_time = datetime.now()
        flow_manager.stop_service()

        print("\nStart :\n\t" + str(start_time))
        print("Record duration :\n\t" + str(end_time - start_time))


if __name__ == '__main__':
    # parser = argparse.ArgumentParser(description='Network feature extractor for RaspberryPi')
    # parser.add_argument("-c", "--config", dest="config", required=False, type=str, help="Config file path\nThis must "
    #                                                                                   "be an absolute path otherwise "
    #                                                                                    "the config cannot be loaded")
    # parser.add_argument("-e", "--heuristics", dest="heuristics", required=False, type=str,
    #                    help="JSON file of containing each feature id\nThis must be an absolute path otherwise the "
    #                         "config cannot be loaded\ne.g. {\n\t'sourceMac': 1,\n\t'destinationMac': 2, \n\t...\n}")
    # args = parser.parse_args(sys.argv)
    conf = "ids_config.conf"
    heuristics = None

    # if args.config is not None and args.config != "":
    #    conf = args.config
    # if args.heuristics is not None and args.heuristics != "":
    #    heuristics = json.load(open(args.config, mode='r'))

    main(config_filename=conf)
