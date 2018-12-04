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


HEURISTICS = {
        "sourceMac": 1,
        "destinationMac": 2,
        "sourceIp": 3,
        "destinationIp": 4,
        "arpRequest": 5,
        "arpReply": 6,
        "flowStartTime": 7,
        "flowEndTime": 8,
        "flowDurationMilliseconds": 9,
        "deltaTimeBetweenPackets": 10,
        "flowRate": 11,
        "minSize": 12,
        "maxSize": 13,
        "packetSizes": 14,
        "deltaSizeBytes": 15,
        "sumSizeBytes": 16,
        "meanPacketSizeFromSource": 17,
        "meanPacketSizeFromDestination": 18,
        "sourceToDestinationSizeBytes": 19,
        "destinationToSourceSizeBytes": 20,
        "sourceToDestinationPacketNumber": 21,
        "destinationToSourcePacketNumber": 22,
        "totalPacket": 23,
        "direction": 24,
        "countSameDestinationAddress": 25,
        "countSameSourceAddressDestinationPort": 26,
        "countSameDestinationAddressSourcePort": 27,
        "countSameSourceDestinationAddress": 28,
        "minTTL": 29,
        "maxTTL": 30,
        "sourceToDestinationTTL": 31,
        "destinationToSourceTTL": 32
    }


class SettingParser(object):

    def __init__(self, filename="ids_config.conf", heuristics: dict = HEURISTICS):
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

    def get_features(self, section: str = "FEATURES", key: str = "Features", default: list = list(0,)):
        features = []
        str_features = self.get_str_value(section, key, "ALL")

        if str_features.lower() == "all":
            return default

        for feature in str_features.replace(" ", "").lower().split(','):
            if feature == "all":
                return default
            try:
                features.append(self.__heuristics[feature])
            except KeyError:
                pass

        return features
