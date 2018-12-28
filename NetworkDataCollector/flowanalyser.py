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

from idsconfigparser import SettingParser
from sklearn.preprocessing import MinMaxScaler
import multiprocessing
import numpy
import keras
import csv
import os
import mimetypes


class FlowAnalyserInitError(Exception):
    pass


class FlowAnalyser(multiprocessing.Process):

    def __init__(self, config_path_file: str, queue: multiprocessing.Queue):
        super().__init__(name="Flow analysis process")

        config_parser = SettingParser(filename=config_path_file, allow_no_value=True)
        model_path_file = config_parser.get_str_value("GENERAL", "ModelPathFile", "")
        weights_path_file = config_parser.get_str_value("GENERAL", "WeightsPathFile", "")
        training_csv_dataset = config_parser.get_str_value("GENERAL", "TrainingDatasetPathFile", "")

        if model_path_file == "" or weights_path_file == "" or training_csv_dataset == "":
            raise DeepAnalyserInitError("Invalid configuration")

        self.__prediction_headers = []
        for element in config_parser.get_all_value_from_section(section="PREDICTION-HEADERS").keys():
            if element != "" and element is not None:
                self.__prediction_headers += [element]

        self.__features = []
        for element in config_parser.get_all_value_from_section(section="FEATURES").keys():
            if element != "" and element is not None:
                self.__features += [element]

        self.__flow_queue = queue

        try:
            if os.path.exists(model_path_file) and os.path.isfile(model_path_file) and "json" in mimetypes.guess_type(
                    model_path_file, False)[0].lower() and os.path.exists(weights_path_file) and os.path.isfile\
                        (weights_path_file):
                with open(model_path_file, 'r') as json_model:
                    self.__model = keras.models.model_from_json(json_model.read())
                # load weights into new model
                self.__model.load_weights(weights_path_file)
            else:
                raise DeepAnalyserInitError("Model loading error: model or weights files do not exist or are not "
                                            "Keras-readable files\nThe model file must be a Keras-readable JSON file "
                                            "and the weights file must be a Keras-readable H5 file")
        except Exception as e:
            raise DeepAnalyserInitError("Model loading error: " + str(e))

        self.__scaler = MinMaxScaler()

        try:
            if os.path.exists(training_csv_dataset) and os.path.isfile(training_csv_dataset) and\
                    ("csv" in mimetypes.guess_type(training_csv_dataset, False)[0].lower() or "separated-values" in
                        mimetypes.guess_type(training_csv_dataset, False)[0].lower()):
                data = numpy.array(list(csv.reader(open(training_csv_dataset), delimiter=",")))

                x_train = data  # [:, :]

                try:
                    x_train = x_train.astype(float)
                except (ValueError, numpy.ComplexWarning) as e:
                    raise DeepAnalyserInitError("Error during training dataset scaling: " + str(e))

                self.__scaler.fit(x_train)
            else:
                raise DeepAnalyserInitError("Training data loading error: training dataset does not exist or is not a "
                                            "CSV file")
        except Exception as e:
            raise DeepAnalyserInitError("Training data loading error: " + str(e))

    def run(self):
        while 1:
            try:
                if not self.__flow_queue.empty():
                    flow = self.__flow_queue.get(timeout=2)
                    listed_flow = []
                    listed_flow += [0 for i in range(len(self.__features))]

                    for key in flow.keys():
                        try:
                            listed_flow[self.__features.index(key.lower())] = flow[key.lower()]
                        except ValueError:
                            pass

                    data_line = numpy.array(",".join(listed_flow))

                    print(", ".join(listed_flow))

                    data_line.astype(float)
                    data_line = data_line.reshape([1, len(self.__features)])
                    data_line = self.__scaler.transform(data_line)

                    data_line = data_line.reshape([1, len(self.__features), 1, 1])

                    print("--- Prediction ---")
                    print(self.__model.predict(data_line, headers=self.__prediction_headers))
                    print("--- \t ---")
            except KeyboardInterrupt:
                break
