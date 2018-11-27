# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# direction Copyright(c) 2018 Félix Molina.
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

import enum


class Direction(enum.Enum):
    SourceToDestination = 0
    DestinationToSource = 1
    BiDirectional = 2


class Flag(enum.Enum):
    RES = 0
    NS = 1
    CWR = 2
    ECN = 3
    URG = 4
    ACK = 5
    PUSH = 6
    RESET = 7
    SYN = 8
    FIN = 9


class ConnectionState(enum.Enum):
    ESTABLISHMENT = 0
    TERMINATION = 1
    SYN_SRC = 2
    SYN_DST = 3
    ACK_SRC = 4
    ACK_DST = 5
    FIN_SRC = 6
    FIN_DST = 7


FLAGS = {
    Flag.RES: 'flags_res',
    Flag.NS: 'flags_ns',
    Flag.CWR: 'flags_cwr',
    Flag.ECN: 'flags_ecn',
    Flag.URG: 'flags_urg',
    Flag.ACK: 'flags_ack',
    Flag.PUSH: 'flags_push',
    Flag.RESET: 'flags_reset',
    Flag.SYN: 'flags_syn',
    Flag.FIN: 'flags_fin'
}


CONNECTION_FLAGS = {
    ConnectionState.ESTABLISHMENT: {
        ConnectionState.SYN_SRC: 0,
        ConnectionState.SYN_DST: 0,
        ConnectionState.ACK_SRC: 0,
        ConnectionState.ACK_DST: 0
    },
    ConnectionState.TERMINATION: {
        ConnectionState.FIN_SRC: 0,
        ConnectionState.FIN_DST: 0,
        ConnectionState.ACK_SRC: 0,
        ConnectionState.ACK_DST: 0
    }
}


COUNTERS = {
    "ct_dst_ltm": [],
    "ct_src_dport_ltm": [],
    "ct_dst_sport_ltm": [],
    "ct_dst_src_ltm": []
}
