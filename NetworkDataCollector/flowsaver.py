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

from multiprocessing.queues import Empty
import multiprocessing
import json
import time
import os
import platform


def get_current_milli():
    return int(round(time.time() * 1000))


def path_calculation(directory_path: str, filename: str, file_index: int):
    if directory_path == "." or directory_path == "" or directory_path == "./" or directory_path == "/" or \
                    directory_path == ".\\" or directory_path == "\\":
        directory_path = os.path.curdir

    if directory_path[-1] == "\\" or directory_path[-1] == "/":
        return directory_path + filename + "_" + str(file_index)
    else:
        if "windows" in platform.system().lower():
            return directory_path + "\\" + filename + "_" + str(file_index)
        else:
            return directory_path + "/" + filename + "_" + str(file_index)


class FlowSaver(multiprocessing.Process):

    def __init__(self, directory_path: str = None, filename: str = None, file_size_limit: str = "100M",
                 queue: multiprocessing.Queue = None, file_type: str = "both"):
        super().__init__(name="Flow saving process")

        if "both" in file_type.lower():
            self.__write_csv = True
            self.__write_json = True
        elif file_type.lower() == "csv":
            self.__write_csv = True
            self.__write_json = False
        elif file_type.lower() == "json":
            self.__write_csv = False
            self.__write_json = True
        else:
            self.__write_csv = True
            self.__write_json = True

        self.__file_index = 1
        self.__record_id = 0

        self.__queue_data = queue

        try:
            if file_size_limit.find("K") != -1:
                self.__file_size_limit = int(file_size_limit.split("K")[0].replace(' ', '')) * (10 ** 3) if int(
                    file_size_limit.split("K")[0].replace(' ', '')) > 1 else (10 ** 3)
            elif file_size_limit.find("k") != -1:
                self.__file_size_limit = int(file_size_limit.split("k")[0].replace(' ', '')) * (10 ** 3) if int(
                    file_size_limit.split("k")[0].replace(' ', '')) > 1 else (10 ** 3)
            elif file_size_limit.find("M") != -1:
                self.__file_size_limit = int(file_size_limit.split("M")[0].replace(' ', '')) * (10 ** 6) if int(
                    file_size_limit.split("M")[0].replace(' ', '')) > 1 else (10 ** 6)
            elif file_size_limit.find("m") != -1:
                self.__file_size_limit = int(file_size_limit.split("m")[0].replace(' ', '')) * (10 ** 6) if int(
                    file_size_limit.split("m")[0].replace(' ', '')) > 1 else (10 ** 6)
            elif file_size_limit.find("G") != -1:
                self.__file_size_limit = int(file_size_limit.split("G")[0].replace(' ', '')) * (10 ** 9) if int(
                    file_size_limit.split("G")[0].replace(' ', '')) > 1 else (10 ** 9)
            elif file_size_limit.find("g") != -1:
                self.__file_size_limit = int(file_size_limit.split("g")[0].replace(' ', '')) * (10 ** 9) if int(
                    file_size_limit.split("g")[0].replace(' ', '')) > 1 else (10 ** 9)
            else:
                self.__file_size_limit = 10 * (10 ** 6)
        except TypeError:
            self.__file_size_limit = 10 * (10 ** 6)

        if not os.path.isdir(directory_path):
            self.__directory_path = ''
        else:
            self.__directory_path = directory_path

        if filename is None or filename == "":
            self.__filename = "flow_saver_" + str(get_current_milli())
        else:
            self.__filename = filename

        self.__path = path_calculation(self.__directory_path, self.__filename + "_csv", self.__file_index)

        with open(self.__path, 'w+') as csv_file:
            fieldnames = csv_file.readline()
            if fieldnames == "" or fieldnames is None:
                self.__fieldnames = ["id"]
            else:
                self.__fieldnames = fieldnames.lower().replace(' ', '').split(',')

        self.__json_writer = {}
        self.__csv_writer = [",".join(self.__fieldnames)]

    def run(self):
        while True:
            try:
                data = self.__queue_data.get(timeout=2)
                if data is None:
                    pass

                if str(data).encode(encoding="utf-8").__len__() + \
                        str(self.__json_writer).encode(encoding="utf-8").__len__() > self.__file_size_limit \
                        or str(data).encode(encoding="utf-8").__len__() + str(self.__csv_writer).encode(
                            encoding="utf-8").__len__() > self.__file_size_limit:

                    if self.__write_csv:
                        self.__path = path_calculation(self.__directory_path, self.__filename + "_csv",
                                                       self.__file_index)
                        with open(self.__path, 'w') as csv_file:
                            for row in self.__csv_writer:
                                csv_file.write(row + "\n")

                        self.__csv_writer = [",".join(self.__fieldnames)]

                    if self.__write_json:
                        self.__path = path_calculation(self.__directory_path, self.__filename + "_json",
                                                       self.__file_index)
                        with open(self.__path, 'w') as json_file:
                            json.dump(self.__json_writer, json_file, ensure_ascii=True)

                        self.__json_writer = {}

                    self.__file_index += 1

                # Check if the data size add to the file size is not greater than the file size limit

                if self.__write_csv:
                    write = []
                    write += ["0"] * len(self.__fieldnames)
                    write[0] = str(self.__record_id)

                    for key in data.keys():
                        if key.lower() in self.__fieldnames:
                            write[self.__fieldnames.index(key.lower())] = str(data[key])
                        else:
                            if "flowid" not in key.lower():
                                self.__fieldnames += [str(key.lower())]
                                write += [str(data[key])]

                    self.__csv_writer[0] = ",".join(self.__fieldnames)
                    self.__csv_writer += [",".join(write)]

                if self.__write_json:
                    write = {}

                    for key in data.keys():
                        if "flowid" not in key.lower():
                            write[key.lower()] = str(data[key])
                    write["recordid"] = str(self.__record_id)

                    self.__json_writer[str(self.__record_id)] = write

                self.__record_id += 1
            except KeyboardInterrupt:
                break
            except Empty:
                pass
            except Exception as e:
                print(str(e))
                pass

        if self.__write_csv:
            self.__path = path_calculation(self.__directory_path, self.__filename + "_csv",
                                           self.__file_index)
            with open(self.__path, 'w') as csv_file:
                for row in self.__csv_writer:
                    tmp_s = row + "\n"
                    csv_file.write(tmp_s)

        if self.__write_json:
            self.__path = path_calculation(self.__directory_path, self.__filename + "_json",
                                           self.__file_index)
            with open(self.__path, 'w') as json_file:
                json.dump(self.__json_writer, json_file, ensure_ascii=True)
