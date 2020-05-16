import argparse
import urllib.request
import json
import socket
import re


class Traceroute:
    proto_icmp = socket.getprotobyname('icmp')
    proto_udp = socket.getprotobyname('udp')

    def __init__(self, address):
        self.dst_ip = address
        self.port = 33434

    def run(self, ttl=255, timeout=0.3):
        for t in range(1, ttl + 1):
            r_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                   self.proto_icmp)
            s_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   self.proto_udp)
            s_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, t)
            r_sock.settimeout(timeout)
            r_sock.bind(('', self.port))
            s_sock.sendto(bytes("", 'UTF-8'), (self.dst_ip, self.port))

            try:
                _, address = r_sock.recvfrom(512)
                address = address[0]
            except socket.error:
                address = None
            finally:
                r_sock.close()
                s_sock.close()

            yield f"{t}. {Whois.check(address)}\r\n"

            if address == self.dst_ip:
                break


class Whois:
    _service = 'http://ip-api.com/json/'
    _info_fields = 'fields=status,message,countryCode,as,reverse,query'

    @staticmethod
    def check(ip):
        if not ip:
            return '*'

        with urllib.request.urlopen(
                f'{Whois._service}{ip}?{Whois._info_fields}') as url:
            data = json.loads(url.read().decode())
            return Whois._format_address_data(data)

    _as_regex = re.compile(r'AS(\d{4})')

    @staticmethod
    def _format_address_data(data):
        info = []
        if data['status'] == 'fail':
            info.append('local')
        else:
            info.append(data['reverse'])
            _as = re.match(Whois._as_regex, data['as'])
            if _as:
                info.append(_as.group(1))
            info.append(data['countryCode'])

        return f"{data['query']}\n{','.join(s for s in info if s)}"


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('address', type=str, help='IP address or DNS name')
    return parser.parse_args()


def _get_ip(address):
    try:
        socket.inet_aton(address)
        return address
    except socket.error:
        return socket.gethostbyname(address)


if __name__ == '__main__':
    args = parse_arguments()

    try:
        address = _get_ip(args.address)
    except socket.error:
        print(f'{args.address} is invalid')
        exit(1)

    try:
        traceroute = Traceroute(address)
        [print(entry) for entry in traceroute.run()]
    except socket.error:
        print('couldnt run traceroute')
        exit(1)
