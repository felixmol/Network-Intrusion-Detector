import socket
import json


class SendingFlowsException(Exception):
    pass


class InvalidIPv4(Exception):
    pass


def check_ipv4_address(address) -> bool:
    try:
        if len(address.split(".")) == 4:
            for elem in address.split("."):
                if int(elem) < 0 or int(elem) > 255:
                    return False
            return True
        else:
            return False
    except Exception as e:
        raise InvalidIPv4("Invalid IPv4 address: " + str(e))


def send_data(address, port, flows):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as flow_socket:
        try:
            flow_socket.connect((address, port))
            flow_socket.sendall(bytes(json.dumps(flows, ensure_ascii=True), encoding="utf-8"))
        except Exception as e:
            raise SendingFlowsException(str(e))
