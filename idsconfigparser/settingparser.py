# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# setting parser Copyright(c) 2018 Félix Molina.
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

import configparser
import os


HEURISTICS = [
    "flowid",
    "sourcemac",
    "destinationmac",
    "sourceip",
    "destinationip",
    "arprequest",
    "arpreply",
    "flowstarttime",
    "flowendtime",
    "flowdurationmilliseconds",
    "deltatimebetweenpackets",
    "flowrate",
    "minsize",
    "maxsize",
    "packetsizes",
    "deltasizebytes",
    "sumsizebytes",
    "meanpacketsizefromsource",
    "meanpacketsizefromdestination",
    "sourcetodestinationsizebytes",
    "destinationtosourcesizebytes",
    "sourcetodestinationpacketnumber",
    "destinationtosourcepacketnumber",
    "totalpacket",
    "direction",
    "countsamedestinationaddress",
    "countsamesourceaddressdestinationport",
    "countsamedestinationaddresssourceport",
    "countsamesourcedestinationaddress",
    "minttl",
    "maxttl",
    "sourcetodestinationttl",
    "destinationtosourcettl",
    "closed"
]


class SettingParser(object):

    def __init__(self, filename="ids_config.conf", heuristics: list = HEURISTICS):
        super().__init__()

        self.error = "No error"
        self.__config_parser = configparser.ConfigParser()
        self.__filename = filename

        if os.path.exists(self.__filename) and os.path.isfile(self.__filename):
            try:
                self.__config_parser.read(filename, encoding="utf-8")
            except Exception as e:
                self.error = "Impossible to load " + self.__filename + ".\nCheck the content syntax.\n" + str(e)
        else:
            self.error = "Impossible to find " + self.__filename + ".\nCheck that is an absolute path."
            self.__filename = "ids_config_parser.conf"

        self.__heuristics = heuristics

    def get_int_value(self, section: str, key: str, default: int):
        return self.__config_parser.getint(section=section, option=key, fallback=default)

    def get_float_value(self, section: str, key: str, default: float):
        return self.__config_parser.getfloat(section=section, option=key, fallback=default)

    def get_str_value(self, section: str, key: str, default: str):
        return self.__config_parser.get(section=section, option=key, fallback=default)

    def get_bool_value(self, section: str, key: str, default: bool):
        return self.__config_parser.getboolean(section=section, option=key, fallback=default)

    def get_features(self, section: str = "FEATURES", key: str = "Features", default: list = list(["all"])):
        features = []
        str_features = self.get_str_value(section, key, "ALL")

        if "all" in str_features.lower():
            return default

        for feature in str_features.replace(" ", "").lower().split(','):
            if feature == "all":
                return default

            if feature in self.__heuristics:
                features.append(feature)

        return features
