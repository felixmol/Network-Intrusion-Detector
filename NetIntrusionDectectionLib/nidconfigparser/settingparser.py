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


class SettingParser(object):

    def __init__(self, filename="nid_extractor.conf", allow_no_value=False):
        super().__init__()

        self.error = "no error"
        self.__config_parser = configparser.ConfigParser(allow_no_value=allow_no_value)
        self.__filename = filename

        if os.path.exists(self.__filename) and os.path.isfile(self.__filename):
            try:
                self.__config_parser.read(filename, encoding="utf-8")
            except Exception as e:
                self.error = "Impossible to load " + self.__filename + ".\nCheck the content syntax.\n" + str(e)
        else:
            self.error = "Impossible to find " + self.__filename + ".\nCheck that is an absolute path."
            self.__filename = "ids_config_parser.conf"

    def get_int_value(self, section: str, key: str, default: int) -> int:
        return self.__config_parser.getint(section=section, option=key, fallback=default)

    def get_float_value(self, section: str, key: str, default: float) -> float:
        return self.__config_parser.getfloat(section=section, option=key, fallback=default)

    def get_str_value(self, section: str, key: str, default: str) -> str:
        return self.__config_parser.get(section=section, option=key, fallback=default)

    def get_bool_value(self, section: str, key: str, default: bool) -> bool:
        return self.__config_parser.getboolean(section=section, option=key, fallback=default)

    def get_list_value(self, section: str, key: str, separator: str = ',', default: list = list()) -> list:
        str_value = self.get_str_value(section=section, key=key, default='')

        if str_value is '' or "all" in str_value:
            return default

        return str_value.lower().replace(' ', '').split(sep=separator)

    def get_all_value_from_section(self, section: str, default: dict = None) -> dict:
        default_value = default if default is not None else {}

        if section not in self.__config_parser.sections():
            return default_value

        return self.__config_parser[section]
