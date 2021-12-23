import json

import jsonpath
from loguru import logger

from helper import base64_encode, base64_decode, check_ip


class BaseConf:

    def check(self):
        '检查是否符合免流'
        raise NotImplementedError

    def extract(self):
        '提取数据到成员变量'
        raise NotImplementedError

    def change_host(self, host):
        '替换免流host'
        raise NotImplementedError

    def generate_v2rayn_link(self):
        '生成v2链接'
        raise NotImplementedError

    def generate_clash_proxy(self):
        '生成clash proxies中的单个proxy'
        raise NotImplementedError

    def generate_surfboard_proxy(self):
        '生成surfboard Proxy的单个proxy'
        raise NotImplementedError


class V2rayN(BaseConf):

    def __init__(self, raw_node):
        self._raw_node = raw_node
        self.protocol = ""

        # v2rayN 分享链接格式：https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)

        self.v = "2"
        self.ps = ""
        self.add = ""
        self.port = ""
        self.id = ""
        self.aid = ""
        self.scy = ""
        self.net = ""  # tcp\kcp\ws\h2\quic
        self.type = ""  # (none\http\srtp\utp\wechat-video) *tcp or kcp or QUIC

        self.host = ""
        # 1)http(tcp)->host中间逗号(,)隔开
        # 2)ws->host
        # 3)h2->host
        # 4)QUIC->securty

        self.path = ""
        # 1)ws->path
        # 2)h2->path
        # 3)QUIC->key/Kcp->seed
        # 4)grpc->serviceName

        self.tls: str = ""  # tls
        self.sni = ""

    def check(self):
        parts = self._raw_node.strip().split('://')

        if len(parts) == 2:
            part1 = parts[0].strip()
            if part1 != 'vmess':
                logger.debug(f'无效的协议: {part1}')
                return False

            self.protocol = part1
            try:
                self._raw_node = json.loads(base64_decode(parts[1]))
            except Exception:
                logger.error(f'base64解析v2节点出错: {self._raw_node}')
                return False

            ip = self._raw_node.get('add', "")
            if not check_ip(ip):
                logger.debug(f'无效的ip: {ip}')
                return False

            network = self._raw_node['net']

            if network != "ws" and network != "tcp":
                logger.debug(f'无效的network: {network}')
                return False
        else:
            logger.error(f'无效的节点: {self._raw_node}')
            return False

        return True

    def extract(self):
        for k, v in self._raw_node.items():
            self.__dict__[k] = v

    def change_host(self, host):
        raw_node = self._raw_node
        if isinstance(raw_node, dict):
            raw_node['host'] = host
            if raw_node.get("tls"):
                raw_node['sni'] = host

    def generate_v2rayn_link(self):
        if self._raw_node['net'] == 'tcp':  # 注意
            self._raw_node['type'] = 'http'
        return self.protocol + "://" + base64_encode(json.dumps(self._raw_node, ensure_ascii=False))

    def generate_clash_proxy(self):
        self.extract()
        proxy = {
            "name": self.ps,
            "type": self.protocol,
            "server": self.add,
            "port": self.port,
            "uuid": self.id,
            "alterId": self.aid,
            "cipher": self.scy if self.scy else 'auto',

            # ws
            "tls": True if self.tls else False,
            "skip-cert-verify": True,
            "servername": self.sni,  # priority over wss host

            # common
            "udp": True,
            "network": self.net,

            # ws
            "ws-opts": {
                "path": self.path,
                "headers": {
                    "Host": self.host
                }
            },

            # tcp
            "http-opts": {
                "headers": {
                    "Host": self.host.split(',')
                }
            }
        }

        if self.net == 'ws':
            proxy.pop("http-opts")
        elif self.net == 'tcp':
            proxy['network'] = 'http'
            proxy.pop("tls")
            proxy.pop("skip-cert-verify")
            proxy.pop("servername")
            proxy.pop("ws-opts")

        return proxy

    def generate_surfboard_proxy(self):
        self.extract()

        ws = 'true' if self.net == 'ws' else 'false'
        ws_headers = f'Host:{self.host}'
        tls = 'true' if self.tls else 'false'
        if ws == 'true':  # 是否在check里面处理
            proxy = self.ps, f'{self.protocol}, {self.add}, {self.port}, username={self.id}, ws={ws}, tls={tls}, ws-path={self.path}, ws-headers={ws_headers}, skip-cert-verify=true, sni={self.sni}'
            return proxy
        else:
            logger.info('surfboard不支持http免流')
            return ""

    def __str__(self):
        return str(vars(self))


class Clash(BaseConf):

    def __init__(self, raw_node: dict):
        self._raw_proxy = raw_node

        self.name = ""
        self.type = ""
        self.server = ""
        self.port = ""
        self.uuid = ""
        self.alterId = ""
        self.cipher = ""

        self.udp = False
        self.skip_cert_verify = True

        self.tls = False
        self.servername = ""  # priority over wss host,sni

        self.network = ""

        self.ws_opts = ""
        self.ws_path = ""
        self.ws_host = ""

        self.http_hosts = []

    def check(self) -> bool:
        proxy = self._raw_proxy
        network = proxy.get('network', '')
        protocol = proxy.get('type', '')
        server = proxy.get('server', '')

        # clash配置network为空，可能为ws,也可能为http
        if protocol == 'vmess' and (network == "ws" or network == "http" or network == "") and check_ip(server):
            return True
        logger.debug(f'无效的clash proxy节点')
        return False

    def extract(self):
        proxy = self._raw_proxy

        self.name = proxy.get("name", "")
        self.type = proxy.get('type', '')
        self.server = proxy.get('server', '')
        self.port = proxy.get("port", "")
        self.uuid = proxy.get("uuid", "")
        self.alterId = proxy.get("alterId")
        self.cipher = proxy.get("cipher", "")

        self.udp = proxy.get("udp", True)
        self.tls = proxy.get("tls", False)
        self.skip_cert_verify = proxy.get("skip-cert-verify", True)
        self.servername = proxy.get("servername", "")

        self.network = proxy.get("network", "http")  # clash配置network为空，可能为ws,也可能为http
        proxy['network'] = self.network

        self.ws_path = '/'
        ws_path = jsonpath.jsonpath(proxy, '$.ws-opts.path')
        if ws_path:
            self.ws_path = ws_path[0]

        # ws的host
        ws_host = jsonpath.jsonpath(proxy, '$.ws-opts.headers.Host')
        # tcp http的host
        http_hosts = jsonpath.jsonpath(proxy, '$.http-opts.headers.Host')

        if ws_host:
            self.ws_host = ws_host[0]
        elif http_hosts:
            self.http_hosts = http_hosts[0]

    def change_host(self, host):
        network = self._raw_proxy.get('network', 'http')  # clash配置network为空，可能为ws,也可能为http
        self._raw_proxy['network'] = network

        if network == 'ws':
            ws_path = None
            if self._raw_proxy.get('ws-path'):
                ws_path = self._raw_proxy.pop('ws-path')
            if self._raw_proxy.get('ws-headers'):
                self._raw_proxy.pop('ws-headers')

            # 新版ws-headers和ws-path设置,旧版2022会不支持
            ws_opts = self._raw_proxy.get('ws-opts')
            if isinstance(ws_opts, dict):
                if ws_path:
                    ws_opts['path'] = ws_path

                ws_opts_headers = ws_opts.get('headers')
                if isinstance(ws_opts_headers, dict):
                    ws_opts_headers['Host'] = host
                else:
                    ws_opts['headers'] = {
                        "Host": host
                    }
            else:
                self._raw_proxy["ws-opts"] = {
                    "path": ws_path if ws_path else '/',
                    "headers": {
                        "Host": host
                    }
                }
        elif network == 'http':
            self._raw_proxy["http-opts"] = {
                "headers": {
                    "Host": [host]
                }
            }

        self._raw_proxy['servername'] = host

    def generate_v2rayn_link(self):
        self.extract()
        config = {
            'v': "2",
            'ps': self.name,
            'add': self.server,
            'port': self.port,
            'id': self.uuid,
            'aid': self.alterId,
            'scy': 'auto',
            'net': self.network,
            'type': 'none',
            'host': self.ws_host,
            'path': "/",
            'tls': "",
            'sni': ""
        }

        if self.cipher:
            config['scy'] = self.cipher

        if self.network == 'http':
            config['net'] = 'tcp'
            config['type'] = 'http'
            config['host'] = ','.join(self.http_hosts)

        if self.ws_path:
            config["path"] = self.ws_path

        if self.tls:
            config["tls"] = self.tls

        if self.tls and self.network == "ws":
            config["sni"] = self.ws_host

        return self.type + "://" + base64_encode(json.dumps(config, ensure_ascii=False))

    def generate_clash_proxy(self):
        return self._raw_proxy

    def generate_surfboard_proxy(self):
        self.extract()
        ws = 'true' if self.network == 'ws' else 'false'
        ws_headers = f'host:{self.ws_host}'
        tls = 'true' if self.tls else 'false'
        skip_cert_verify = 'true' if self.skip_cert_verify else 'false'
        if ws:
            proxy = self.name, f'{self.type}, {self.server}, {self.port}, username={self.uuid}, ws={ws}, tls={tls}, ws-path={self.ws_path}, ws-headers={ws_headers}, skip-cert-verify={skip_cert_verify}, sni={self.servername}'
            return proxy
        else:
            logger.info('surfboard不支持http免流')
            return ""

    def __str__(self):
        return str(vars(self))
