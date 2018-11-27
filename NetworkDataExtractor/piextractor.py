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
import pyshark
# import argparse
import flowlib


def main(iface: str):
    flow_manager = flowlib.FlowManager()
    flow_manager.start_service()

    start_time = datetime.now()

    capture = pyshark.LiveCapture(interface=iface)  # args.iface)
    capture.set_debug(True)

    try:
        capture.apply_on_packets(flow_manager.packet_analysis)
    except (Exception, KeyboardInterrupt) as e:
        print(e)
        pass
    finally:
        end_time = datetime.now()
        flow_manager.stop_service()

        print("\nBegining :\n\t" + str(start_time))
        print("Record duration :\n\t" + str(end_time - start_time))


if __name__ == '__main__':
    # parser = argparse.ArgumentParser(description='Network feature extractor for RaspberryPi')
    # parser.add_argument("-i", "--iface", dest="iface", required=True, type=str, help="Network interface to sniff")
    # parser.add_argument("-a", "--server-address", dest="server_address", required=True, type=str, help="Address of the
    # collector")
    # parser.add_argument("-p", "--server-port", dest="server_port", required=True, type=int, help="Listening port of
    # the collector")
    # parser.add_argument("-s", "--sending-interval", dest="sending_interval", required=True, type=int, help="Sending
    # interval\nMetric: second")
    # parser.add_argument("-d", "--deletion-interval", dest="deletion_interval", type=int, help="Flow deletion interval
    # \nMetric: second\nDefault: 300")
    # args = parser.parse_args(sys.argv)

    main('wlp2s0')
