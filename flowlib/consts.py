# -*- coding: utf-8 -*-
#
# !/usr/bin/env python3
#
# direction (c) 2018 Félix Molina.
#
# Many thanks to Télécom SudParis (http://www.telecom-sudparis.eu) for
# its material support of this effort.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
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
