# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# deep analyser Copyright(c) 2018 Félix Molina.
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

from sklearn.preprocessing import MinMaxScaler
import multiprocessing
import numpy
import keras
import csv
import json


class DeepAnalyserInitError(Exception):
    pass


class DeepAnalyser(multiprocessing.Process):

    def __init__(self, queue):
        super().__init__(name="Deep analysis process")
        print("* Deep analyser initialisation ...")

        self.__flow_queue = queue

        try:
            with open('model.json', 'r') as json_model:
                self.__model = keras.models.model_from_json(json_model.read())
            # load weights into new model
            self.__model.load_weights("model.h5")
        except Exception as e:
            raise DeepAnalyserInitError("Model loading error: " + str(e))

        self.__scaler = MinMaxScaler()

        try:
            data = numpy.array(list(csv.reader(open("Data/UNSW-NB15/UNSW_NB15_training-set.csv"), delimiter=",")))

            x_train = data[:, [1, 6, 7, 8, 9, 10, 11, 12, 13, 27, 28, 32, 33, 34, 35, 36]]
            x_train = x_train.astype(float)
            self.__scaler.fit(x_train)
        except Exception as e:
            raise DeepAnalyserInitError("Training data loading error: " + str(e))

        print("* Deep analyser initialisation finished")

    def run(self):
        while 1:
            try:
                if not self.__flow_queue.empty():
                    flow = json.loads(self.__flow_queue.get(), encoding="utf-8")
                    flow_list = []

                    for elem in flow.values():
                        flow_list += [str(elem)]

                    data_line = numpy.array(",".join(flow_list))

                    print(data_line)
#                    data_line.astype(float)
#                    data_line = data_line.reshape([1, 16])
#                    data_line = self.__scaler.transform(data_line)
#
#                    data_line = data_line.reshape([1, 16, 1, 1])

#                    print("--- Prediction ---")
#                    print(self.__model.predict(data_line, headers=['Analysis', 'Backdoor', 'DoS', 'Exploits', 'Fuzzers',
#                                                                   'Generic', 'Normal', 'Reconnaissance', 'Shellcode',
#                                                                   'Worms']))
#                    print("--- \t ---")
            except (KeyboardInterrupt):
                break

    def start(self):
        print("[+] Deep analysis service started")
        super().start()

    def join(self, timeout=None):
        super().join(timeout=timeout)
        print("[-] Deep analysis service stopped")
