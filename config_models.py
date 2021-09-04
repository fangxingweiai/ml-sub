import json

import jsonpath

from helper import base64_encode, base64_decode, check_ip


class V2rayN:
    def __init__(self, **kwargs):
        self.protocol = kwargs.get("protocol", "")

        # v2rayN 分享链接格式：https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)

        self.v = kwargs.get("v", "2")
        self.ps = kwargs.get("ps", "")
        self.add = kwargs.get("add", "")
        self.port = kwargs.get("port", "")
        self.id = kwargs.get("id", "")
        self.aid = kwargs.get("aid", 0)
        self.scy = kwargs.get("scy", "auto")
        self.net = kwargs.get("net", "")  # tcp\kcp\ws\h2\quic
        self.type = kwargs.get("type", "none")  # (none\http\srtp\utp\wechat-video) *tcp or kcp or QUIC

        self.host = kwargs.get("host", "")
        # 1)http(tcp)->host中间逗号(,)隔开
        # 2)ws->host
        # 3)h2->host
        # 4)QUIC->securty

        self.path = kwargs.get("path", "/")
        # 1)ws->path
        # 2)h2->path
        # 3)QUIC->key/Kcp->seed
        # 4)grpc->serviceName

        self.tls: str = kwargs.get("tls", "")  # tls
        self.sni = kwargs.get("sni", "")

    def generate_v2rayn_link(self):
        config = vars(self)
        protocol = config.pop('protocol')
        if self.tls:
            config['sni'] = self.host
        else:
            config['sni'] = ""
        return protocol + "://" + base64_encode(json.dumps(config, ensure_ascii=False))

    def extract_from_base64_link(self, link: str):
        protocol, base64_config = link.split('://')
        self.protocol = protocol
        json_config = json.loads(base64_decode(base64_config))

        for k, v in json_config.items():
            if k in self.__dict__.keys():
                self.__dict__[k] = v

        if not check_ip(self.add):
            return False
        return True

    def __str__(self):
        return str(vars(self))


class Clash:
    def __init__(self, **kwargs):
        self.protocol = kwargs.get('protocol', "")

        self.name = kwargs.get("name", "")
        self.type = kwargs.get("type", "")
        self.server = kwargs.get("server", "")
        self.port = kwargs.get("port", "")
        self.uuid = kwargs.get("uuid", "")
        self.alterId = kwargs.get("alterId", "")
        self.cipher = kwargs.get("cipher", "auto")

        self.udp: bool = kwargs.get("udp", True)
        self.tls: bool = kwargs.get("tls", False)
        self.skip_cert_verify: bool = kwargs.get("skip-cert-verify", True)
        self.servername = kwargs.get("servername", "")  # priority over wss host,sni
        self.network = kwargs.get("network", "")
        self.ws_path = kwargs.get("ws-path", "")
        self.host = kwargs.get("Host", "")

    def extract(self, json_proxy: dict):
        self.server = json_proxy["server"]
        if not check_ip(self.server):
            return False

        self.protocol = json_proxy["type"]

        self.name = json_proxy["name"]
        self.type = json_proxy["type"]

        self.port = json_proxy["port"]
        self.uuid = json_proxy.get("uuid")
        self.alterId = json_proxy.get("alterId")
        self.cipher = json_proxy.get("cipher", "auto")

        self.udp = json_proxy.get("udp", True)
        self.tls = json_proxy.get("tls", False)
        self.skip_cert_verify = json_proxy.get("skip-cert-verify", True)
        self.servername = json_proxy.get("servername", "")
        self.network = json_proxy.get("network", "")
        self.ws_path = json_proxy.get("ws-path", "/")

        # ws的host
        ws_host = jsonpath.jsonpath(json_proxy, '$.ws-headers.Host')
        # tcp http的host
        http_hosts = jsonpath.jsonpath(json_proxy, '$.http-opts.headers.Host')

        if ws_host:
            self.host = ws_host[0]
        elif http_hosts:
            self.host = http_hosts

        return True

    def generate_v2rayn_link(self):
        config = {
            'v': "2",
            'ps': self.name,
            'add': self.server,
            'port': self.port,
            'id': self.uuid,
            'aid': self.alterId,
            'scy': self.cipher,
            'net': self.network,
            'type': 'none',
            'host': ','.join(self.host) if isinstance(self.host, list) else self.host,
            'path': self.ws_path,
            'tls': 'tls' if self.tls else "",
            'sni': self.host if self.tls else ""
        }

        if self.network == 'http' or self.network == "":
            config['net'] = 'tcp'
            config['type'] = 'http'

        return self.protocol + "://" + base64_encode(json.dumps(config, ensure_ascii=False))

    def __str__(self):
        return str(vars(self))


if __name__ == '__main__':
    url = "https://pub-api-1.bianyuan.xyz/sub?target=clash&url=https%3A%2F%2Fyyjsd.top%2Fapi%2Fv1%2Fclient%2Fsubscribe%3Ftoken%3D51a42767197ef3d7b3e16005531f4647%7C&insert=false"
    b64_link_ws = "vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIvCfh7fwn4e6IOS/hOe9l+aWryIsDQogICJhZGQiOiAiNDYuMjkuMTY1LjE0NSIsDQogICJwb3J0IjogIjgwIiwNCiAgImlkIjogImI1ODU3YWQ3LWUyNGMtNGUxZi1hOTYyLTkzZjQ3YmJlNTg3MyIsDQogICJhaWQiOiAiMSIsDQogICJzY3kiOiAiYXV0byIsDQogICJuZXQiOiAid3MiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiYS4xODkuY24iLA0KICAicGF0aCI6ICIvIiwNCiAgInRscyI6ICJ0bHMiLA0KICAic25pIjogImEuMTg5LmNuIg0KfQ=="
    b64_link_tcp = "vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogImF6MTB0Y3AiLA0KICAiYWRkIjogIjQwLjgzLjEyMC45MyIsDQogICJwb3J0IjogIjgwIiwNCiAgImlkIjogImI1ODU3YWQ3LWUyNGMtNGUxZi1hOTYyLTkzZjQ3YmJlNTg3MyIsDQogICJhaWQiOiAiMSIsDQogICJzY3kiOiAiYXV0byIsDQogICJuZXQiOiAidGNwIiwNCiAgInR5cGUiOiAiaHR0cCIsDQogICJob3N0IjogInd3d3cuYmFpZHUuY29tIiwNCiAgInBhdGgiOiAiLyIsDQogICJ0bHMiOiAiIiwNCiAgInNuaSI6ICJ3d3d3LmJhaWR1LmNvbSINCn0="
    import requests
    import yaml
    import pprint

    v = V2rayN()
    print(v.extract_from_base64_link(b64_link_tcp))
    v.host = 'jd.com'
    print(v)
    print(v.generate_v2rayn_link())
    print(v)

    ############################################################
    # proxies = {
    #     'http': "http://127.0.0.1:7891",
    #     'https': "https://127.0.0.1:7891",
    # }
    #
    # res = requests.get(url, proxies=proxies, verify=False)
    # json_data = yaml.load(res.text)
    # for i in json_data['proxies']:
    #     pprint.pprint(i)
    #     c = Clash()
    #     c.extract(i)
    #     c.Host = 'a.189.cn'
    #     print(c.generate_v2rayN_link())
    ###############################################################
    print(v.__class__)
