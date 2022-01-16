import json

import jsonpath
from loguru import logger

from helper import base64_encode, base64_decode, check_ip


class ProxyNode(object):

    def __init__(self):
        self._protocol = None
        # v2rayN 分享链接格式：https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
        self.v2 = None
        # {
        #     "v": "2",
        #     "ps": "",
        #     "add": "",
        #     "port": "",
        #     "id": "",
        #     "aid": "",
        #     "scy": "",
        #     "net": "",  # tcp\kcp\ws\h2\quic
        #     "type": "",  # (none\http\srtp\utp\wechat-video) *tcp or kcp or QUIC
        #
        #     "host": "",
        #     # 1)http(tcp)->host中间逗号(,)隔开
        #     # 2)ws->host
        #     # 3)h2->host
        #     # 4)QUIC->securty
        #
        #     "path": "",
        #     # 1)ws->path
        #     # 2)h2->path
        #     # 3)QUIC->key/Kcp->seed
        #     # 4)grpc->serviceName
        #
        #     "tls": "",  # tls :str
        #     "sni": "",
        # }

        self.clash = None

    def load(self, proxy_node):
        if isinstance(proxy_node, str):
            parts = proxy_node.strip().split('://')

            if len(parts) == 2:
                part1 = parts[0].strip()
                if part1 != 'vmess':
                    logger.debug(f'无效的协议: {part1}')
                    return False

                self._protocol = part1
                v2_json_node = None
                try:
                    v2_json_node = json.loads(base64_decode(parts[1]))
                    if v2_json_node['net'] == 'tcp':  # 注意
                        v2_json_node['type'] = 'http'
                except:
                    logger.error(f'无效v2格式，base64解析v2节点出错: {v2_json_node}')
                    return False

                ip = v2_json_node.get('add', "")
                if not check_ip(ip):
                    logger.debug(f'无效的ip: {ip}')
                    return False

                network = v2_json_node['net']

                if network != "ws" and network != "tcp":
                    logger.debug(f'无效的network: {network}')
                    return False

                self.v2 = v2_json_node
                self.v2_to_clash()
            else:
                logger.error(f'无效的v2节点: {proxy_node}')
                return False
            return True
        elif isinstance(proxy_node, dict):
            network = proxy_node.get('network', '')
            protocol = proxy_node.get('type', '')
            server = proxy_node.get('server', '')

            if protocol == 'vmess' and (network == "ws" or network == "http" or network == "") and check_ip(server):
                if network == "":  # clash配置network为空，可能为ws,也可能为http
                    proxy_node["network"] = "http"

                self.clash = proxy_node
                self._protocol = protocol
                self.clash_to_v2()
                return True
            logger.debug(f'无效的clash节点: proxy_node')
            return False

    def v2_to_clash(self):
        self.clash = {
            "name": self.v2["ps"],
            "type": self._protocol,
            "server": self.v2["add"],
            "port": self.v2["port"],
            "uuid": self.v2["id"],
            "alterId": self.v2["aid"],
            "cipher": self.v2.get("scy") or 'auto',

            # ws
            "tls": True if self.v2.get("tls") else False,
            # "skip-cert-verify": True,
            "servername": self.v2.get("sni", ""),  # priority over wss host

            # common
            # "udp": True,
            "network": self.v2["net"],

            # ws
            "ws-opts": {
                "path": self.v2.get("path", "/"),
                "headers": {
                    "Host": self.v2.get("host", "")
                }
            },

            # tcp
            "http-opts": {
                "headers": {
                    "Host": self.v2.get("host", "").split(',')
                }
            }
        }

        if self.v2["net"] == 'ws':
            self.clash.pop("http-opts")
        elif self.v2["net"] == 'tcp':
            self.clash['network'] = 'http'
            self.clash.pop("tls")
            # self.clash.pop("skip-cert-verify")
            self.clash.pop("servername")
            self.clash.pop("ws-opts")

    def clash_to_v2(self):
        config = {
            'v': "2",
            'ps': self.clash["name"],
            'add': self.clash["server"],
            'port': self.clash["port"],
            'id': self.clash["uuid"],
            'aid': self.clash["alterId"],
            'scy': self.clash.get("cipher", "auto"),
            'net': self.clash.get("network"),  # clash配置network为空，可能为ws,也可能为http
            'type': 'none',
            'host': "",
            'path': "/",
            'tls': "",
            'sni': ""
        }

        tls = self.clash.get("tls", False)
        if tls:
            config["tls"] = "tls"

        if config["net"] == 'http':
            config["net"] = "tcp"
            config['type'] = 'http'

            # tcp http的host
            http_hosts = jsonpath.jsonpath(self.clash, '$.http-opts.headers.Host')
            if http_hosts:
                config['host'] = ','.join(http_hosts[0])
        else:
            # ws的host
            ws_host = jsonpath.jsonpath(self.clash, '$.ws-opts.headers.Host') or jsonpath.jsonpath(self.clash,
                                                                                                   '$.ws-headers.Host')
            if ws_host:
                config['host'] = ws_host[0]

                if tls:
                    config["sni"] = ws_host[0]

            ws_path = jsonpath.jsonpath(self.clash, '$.ws-opts.path') or jsonpath.jsonpath(self.clash, '$.ws-path')
            if ws_path:
                config['path'] = ws_path[0]

        self.v2 = config

    def change_host(self, host):
        # v2
        self.v2['host'] = host
        if self.v2.get("tls"):
            self.v2['sni'] = host

        # clash
        network = self.clash['network']
        if network == 'ws':
            ws_path = '/'
            if self.clash.get('ws-path'):
                ws_path = self.clash.pop('ws-path')
            if self.clash.get('ws-headers'):
                self.clash.pop('ws-headers')

            # 新版ws-headers和ws-path设置,旧版2022会不支持
            ws_opts = self.clash.get('ws-opts')
            if isinstance(ws_opts, dict):
                ws_opts['path'] = ws_path

                ws_opts_headers = ws_opts.get('headers')
                if isinstance(ws_opts_headers, dict):
                    ws_opts_headers['Host'] = host
                else:
                    ws_opts['headers'] = {
                        "Host": host
                    }
            else:
                self.clash["ws-opts"] = {
                    "path": ws_path,
                    "headers": {
                        "Host": host
                    }
                }

            if self.clash.get('tls'):
                self.clash['servername'] = host
        elif network == 'http':
            self.clash["http-opts"] = {
                "headers": {
                    "Host": [host]
                }
            }

    def generate_v2rayn_link(self):
        return self._protocol + "://" + base64_encode(json.dumps(self.v2, ensure_ascii=False))

    def generate_surfboard_proxy(self):
        ws = 'true' if self.v2["net"] == 'ws' else 'false'
        ws_headers = f'Host:{self.v2.get("host", "")}'
        tls = 'true' if self.v2.get("tls") else 'false'
        if ws == 'true':
            proxy = self.v2[
                        "ps"], f'{self._protocol}, {self.v2["add"]}, {self.v2["port"]}, username={self.v2["id"]}, ws={ws}, tls={tls}, ws-path={self.v2.get("path", "/")}, ws-headers={ws_headers}, skip-cert-verify=true, sni={self.v2.get("sni", "")}'
            return proxy
        else:
            logger.info('surfboard暂不支持http免流')
            return ""

    def generate_clash_proxy(self):
        return self.clash

    def generate_leaf_proxy(self):
        ws = 'true' if self.v2["net"] == 'ws' else 'false'
        ws_host = self.v2.get("host", "")
        tls = 'true' if self.v2.get("tls") else 'false'
        if ws == 'true':
            proxy = self.v2[
                        "ps"], f'{self._protocol}, {self.v2["add"]}, {self.v2["port"]}, username={self.v2["id"]}, ws={ws}, tls={tls}, ws-path={self.v2.get("path", "/")}, ws_host={ws_host}, sni={self.v2.get("sni", "")}'
            return proxy
        else:
            logger.info('Leaf暂不支持http免流')
            return ""


if __name__ == '__main__':
    proxy = "vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIkhvbmdLb25nIiwNCiAgImFkZCI6ICIyMC4xODcuMTE3LjMxIiwNCiAgInBvcnQiOiAiMzYzNTMiLA0KICAiaWQiOiAiYjhkZWU0YTItNzViNi00ZTM2LWZjMjUtZmIxN2U2NGIxOThlIiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ3cyIsDQogICJ0eXBlIjogIm5vbmUiLA0KICAiaG9zdCI6ICIiLA0KICAicGF0aCI6ICIvIiwNCiAgInRscyI6ICIiLA0KICAic25pIjogIiINCn0="
    proxy = {"name": "🇭🇰 试用|香港06解锁流媒体", "type": "vmess", "server": "test.airnode.xyz", "port": 15806,
             "uuid": "d645c3c0-b155-3769-bd5a-57315a6333fd", "alterId": 1, "cipher": "auto", "udp": True,
             "network": "ws", "ws-path": "/blx", "ws-headers": {"Host": "test.airnode.xyz"}}
    node = ProxyNode()
    node.load(proxy)
    node.change_host("a.189.cn")
    print(node.generate_v2rayn_link())
    print(node.generate_clash_proxy())
    print(node.generate_surfboard_proxy())
    print(node.generate_leaf_proxy())
