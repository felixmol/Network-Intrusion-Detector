# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# flow deletion Copyright(c) 2018 Félix Molina.
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

from time import sleep
from multiprocessing import Process


class FlowDeletion(Process):

    def __init__(self, interval, data, id_list):
        super().__init__(name="Flow deletion process")

        self.__interval = interval
        self.__data = data
        self.__removed_ids = id_list

    def run(self):
        while 1:
            try:
                sleep(self.__interval)
                print("deb1")
                for flow in sorted(self.__data, key=lambda x: x.get_start_time()):
                    if flow.is_closed() and len(self.__data) > 100:
                        print("deb2")
                        self.__data.remove(flow)
                        self.__removed_ids += [flow.get_flow_id()]
                        print("deb3")
            except (Exception, KeyboardInterrupt):
                break
