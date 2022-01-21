import json

import jsonpath
from loguru import logger

from core.helper import base64_encode, check_ip, base64_decode


class ProxyNode(object):

    def __init__(self):
        self._protocol = None
        # v2rayN 分享链接格式：https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)
        self.v2 = None

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

                ip = v2_json_node.get('add', '')
                if not check_ip(ip):
                    logger.debug(f'无效的ip: {ip}')
                    return False

                network = v2_json_node.get('net')

                if network != "ws" and network != "tcp":
                    logger.debug(f'无效的network: {network}')
                    return False

                tls = v2_json_node.get('tls')
                if tls == 'tls':
                    logger.debug('有tls，无法免流')  # ？？？
                    return False

                self.v2 = v2_json_node
                self.v2_to_clash()
            else:
                logger.error(f'无效的v2节点: {proxy_node}')
                return False
            return True
        elif isinstance(proxy_node, dict):
            tls = proxy_node.get('tls')
            if tls:
                logger.debug('有tls，无法免流')  # ？？？
                return False

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
            logger.debug(f'无效的clash节点: {proxy_node}')
            return False
        else:
            logger.debug(f'无法识别节点: {proxy_node}')
            return False

    def v2_to_clash(self):
        self.clash = {
            "name": self.v2["ps"],
            "type": self._protocol,
            "server": self.v2["add"],
            "port": int(self.v2["port"]),
            "uuid": self.v2["id"],
            "alterId": int(self.v2["aid"]),
            "cipher": self.v2.get("scy") or 'auto',

            # ws
            "tls": True if self.v2.get("tls") == 'tls' else False,
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

        if not self.clash['tls']:
            self.clash.pop('servername')

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
        if self.v2.get("tls") == 'tls':
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
        tls = 'true' if self.v2.get("tls") == 'tls' else 'false'

        if ws == 'true':
            name = self.v2['ps']
            protocol = self._protocol
            host = ', ' + self.v2['add']
            port = ', ' + self.v2['port']
            uuid = ', username=' + self.v2['id']
            ws = ', ws=' + ws
            ws_path = ', ws-path=' + self.v2.get("path", "/")
            ws_headers = ', ws-headers=' + ws_headers
            sni = ', sni=' + self.v2.get("sni", "") if tls == "true" else ""
            tls = ', tls=' + tls

            proxy = name, protocol + host + port + uuid + ws + ws_path + ws_headers + tls + sni
            return proxy
        else:
            logger.info('surfboard暂不支持http免流')
            return ""

    def generate_clash_proxy(self):
        return self.clash

    def generate_leaf_proxy(self):
        ws = 'true' if self.v2["net"] == 'ws' else 'false'
        ws_host = self.v2.get("host", "")
        tls = 'true' if self.v2.get("tls") == 'tls' else 'false'
        if ws == 'true':
            name = self.v2['ps']
            protocol = self._protocol
            host = ', ' + self.v2['add']
            port = ', ' + self.v2['port']
            uuid = ', username=' + self.v2['id']
            ws = ', ws=' + ws
            ws_path = ', ws-path=' + self.v2.get("path", "/")
            ws_host = ', ' + ws_host
            sni = ', sni=' + self.v2.get("sni", "") if tls == "true" else ""
            tls = ', tls=' + tls

            proxy = name, protocol + host + port + uuid + ws + ws_path + ws_host + tls + sni
            return proxy
        else:
            logger.info('Leaf暂不支持http免流')
            return ""


if __name__ == '__main__':
    proxy = 'Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp4RzBqamNMYmpaN1dAMzQuMjExLjU4Ljg5OjMyOTY5#%e7%be%8e%e5%9b%bd1%7cSC+X+Alink'
    a = base64_decode(proxy)
    print(a)
