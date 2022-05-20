import json
import os
import re
import urllib.parse

from loguru import logger

from core.helper import base64_encode, check_ip, base64_decode


class ProxyNode(object):

    def __init__(self):
        self.protocol = None
        self.name = None

        self.address = None
        self.port = None

        # v2rayN
        self.v = None

        # ss vless trojan
        self.encryption = None
        # ss ssr trojan
        self.password = None

        # vmess
        self.uuid = None
        self.alter_id = None
        self.security = None  # clash:cipher, trojan
        self.network = None  # trojan:type
        self.type = None  # trojan:headerType
        self.host = None
        self.path = None
        self.tls = None  # bool,v2rayN中true时,值为tls
        self.sni = None

        # clash ss ssr vmess trojan
        self.udp = None
        # clash ss vmess trojan
        self.skip_cert_verify = None
        # trojan vless
        self.flow = None
        self.alpn = None
        # trojan
        self.peer = None  # 不知何用
        # ssr
        self.clash_ssr_obfs = None
        self.clash_ssr_protocol = None
        self.clash_ssr_obfs_param = None
        self.clash_ssr_protocol_param = None

        # v2rayN 分享链接格式：https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)

    def load(self, proxy_node):
        logger.info(f'加载节点--> {proxy_node}')
        if isinstance(proxy_node, str) and '://' in proxy_node:
            proxy_node = proxy_node.replace('\r', '').replace('\n', '')
            part1, part2 = proxy_node.strip().split('://')

            self.protocol = part1

            # ss://YWVzLTI1Ni1nY206MTE0NTE0@173.82.232.224:56634#%E6%B5%8B%E8%AF%95
            # ss://YWVzLTI1Ni1nY206WTZSOXBBdHZ4eHptR0NAMTcyLjk5LjE5MC4zNTozMzA2#🇺🇸US_1950
            if self.protocol == 'ss':
                proxy_data, proxy_name = part2.split('#')
                if '@' in proxy_data:
                    self.name = urllib.parse.unquote(proxy_name)

                    proxy_data_res, addr_and_port = proxy_data.split('@')
                    self.address, self.port = addr_and_port.split(':')
                    self.encryption, self.password = base64_decode(proxy_data_res).split(':')
                else:
                    self.name = urllib.parse.unquote(proxy_name)

                    proxy_data = base64_decode(proxy_data)
                    self.encryption, proxy_data_rest, self.port = proxy_data.split(':')
                    self.password, self.address = proxy_data_rest.rsplit('@', 1)  # 密码中可能用@
            elif self.protocol == 'ssr':
                part2 = part2.replace('-', '+').replace('_', '/')
                proxy_data = base64_decode(part2)

                # 183.232.56.182:1254:auth_aes128_md5:chacha20-ietf:plain:bXRidjhu/?remarks=SmFwYW4&protoparam=MTE0ODgyOkx3ZFlMag&obfsparam=dC5tZS92cG5oYXQ
                self.address, self.port, self.clash_ssr_protocol, self.security, self.clash_ssr_obfs, proxy_data_rest = proxy_data.split(
                    ':')

                # bXRidjhu/?remarks=SmFwYW4&protoparam=MTE0ODgyOkx3ZFlMag&obfsparam=dC5tZS92cG5oYXQ
                password_base64, proxy_data_rest = proxy_data_rest.split('/?')
                self.password = base64_decode(password_base64)

                # remarks=SmFwYW4&protoparam=MTE0ODgyOkx3ZFlMag&obfsparam=dC5tZS92cG5oYXQ
                for i in proxy_data_rest.split('&'):
                    if i.startswith('remarks'):
                        self.name = base64_decode(i.removeprefix('remarks='))
                    elif i.startswith('protoparam'):
                        self.clash_ssr_protocol_param = base64_decode(i.removeprefix('protoparam='))
                    elif i.startswith('obfsparam'):
                        self.clash_ssr_obfs_param = base64_decode(i.removeprefix('obfsparam='))
                    else:
                        logger.warning(f'ssr链接未解析参数：{i}')
            elif self.protocol == 'vmess':
                v2rayN_json = None
                try:
                    v2rayN_json = json.loads(base64_decode(part2))
                except:
                    logger.error(f'无效v2格式，base64解析v2节点出错: {v2rayN_json}')
                    return False

                if v2rayN_json['net'] == 'tcp':  # 注意
                    v2rayN_json['type'] = 'http'

                ip = v2rayN_json.get('add', '')
                if not check_ip(ip):
                    logger.debug(f'无效的ip: {ip}')
                    return False
                self.v = v2rayN_json.get('v', 2)
                self.name = v2rayN_json['ps']
                self.address = v2rayN_json['add']
                self.port = v2rayN_json['port']
                self.uuid = v2rayN_json['id']
                self.alter_id = v2rayN_json['aid']
                self.security = v2rayN_json.get('scy')
                self.network = v2rayN_json['net']
                self.type = v2rayN_json['type']
                self.host = v2rayN_json['host']
                self.path = v2rayN_json['path']
                self.tls = True if v2rayN_json['tls'] else None
                self.sni = v2rayN_json.get('sni')
            elif self.protocol == 'trojan':
                self.password, self.address, port_like, trojan_name = re.split(r':|@|#', part2)

                self.name = urllib.parse.unquote(trojan_name)

                if '?' in port_like:
                    port, params = port_like.split('?')

                    param_pair_list = params.split('&')
                    for i in param_pair_list:
                        if i.startswith('peer='):
                            self.peer = i.removeprefix('peer=')
                        elif i.startswith('sni='):
                            self.sni = i.removeprefix('sni=')
                        elif i.startswith('security='):
                            self.security = i.removeprefix('security=')
                        elif i.startswith('type='):
                            self.network = i.removeprefix('type=')
                        elif i.startswith('encryption='):
                            self.encryption = i.removeprefix('encryption=')
                        elif i.startswith('flow='):
                            self.flow = i.removeprefix('flow=')
                        elif i.startswith('headerType='):
                            self.type = i.removeprefix('headerType=')
                        elif i.startswith('host='):
                            self.host = i.removeprefix('host=')
                        elif i.startswith('alpn='):
                            self.alpn = urllib.parse.unquote(i.removeprefix('alpn='))
                        elif i.startswith('allowInsecure='):
                            allow_insecure = i.removeprefix('allowInsecure=')
                            if allow_insecure == '1':
                                self.skip_cert_verify = False
                            else:
                                logger.warning(f'trojan连接中?后面参数allowInsecure未识别：{i}')
                        else:
                            logger.warning(f'trojan连接中?后面未解析解析参数：{i}')
                else:
                    port = port_like

                if port.isnumeric():
                    self.port = port
                else:
                    # 3424/
                    self.port = re.match(r'\d+', port).group()
                    logger.warning(f'trojan连接中port后面出现特殊字符：{port}')
            elif self.protocol == 'vless':
                # vless://72972da9-d188-40c6-83a6-4ec28fde2c0a@cg.rutracker-cn.com:443?path=%2FxxPb49hL0C&security=tls&encryption=none&type=ws&sni=cg.rutracker-cn.com#v2cross.com
                proxy_data, self.name = part2.rsplit('#', 1)
                proxy_data_start, proxy_data_end = proxy_data.split('?')

                # 72972da9-d188-40c6-83a6-4ec28fde2c0a@cg.rutracker-cn.com:443
                self.uuid, self.address, self.port = re.split(r'@|:', proxy_data_start)

                # path=%2FxxPb49hL0C&security=tls&encryption=none&type=ws&sni=cg.rutracker-cn.com
                param_pair_list = proxy_data_end.split('&')
                for i in param_pair_list:
                    if i.startswith('path='):
                        self.path = urllib.parse.unquote(i.removeprefix('path='))
                    elif i.startswith('security='):
                        self.tls = True if 'tls' in i else None
                    elif i.startswith('encryption='):
                        self.encryption = i.removeprefix('encryption=')
                    elif i.startswith('type='):
                        self.network = i.removeprefix('type=')
                    elif i.startswith('sni='):
                        self.sni = i.removeprefix('sni=')
                    elif i.startswith('flow='):
                        self.flow = i.removeprefix('flow=')
                    elif i.startswith('alpn='):
                        self.alpn = i.removeprefix('alpn=')
                    elif i.startswith('host='):
                        self.host = i.removeprefix('host=')
                    elif i.startswith('headerType='):
                        self.type = i.removeprefix('headerType=')
                    else:
                        logger.warning(f'vless链接未解析参数：{i}')

            if self.address and not check_ip(self.address):
                logger.warning(f'节点ip不合法：{self.address}')
                return False
        elif isinstance(proxy_node, dict):
            self.address = proxy_node.get('server', '')
            if not check_ip(self.address):
                logger.warning(f'节点ip不合法：{self.address}')
                return False

            self.name = proxy_node.get('name', '')
            self.protocol = proxy_node.get('type', '')
            self.port = proxy_node.get('port', '')

            if self.protocol == 'ss':
                self.encryption = proxy_node.get('cipher', '')
                self.password = proxy_node.get('password', '')
                self.udp = proxy_node.get('udp')
            elif self.protocol == 'vmess':
                self.uuid = proxy_node.get('uuid', '')
                self.alter_id = proxy_node.get('alterId', '')
                self.security = proxy_node.get('cipher', '')
                self.udp = proxy_node.get('udp')
                self.tls = proxy_node.get('tls')
                self.skip_cert_verify = proxy_node.get('skip-cert-verify')
                self.sni = proxy_node.get('servername')

                self.network = proxy_node.get('network')  # clash配置network为空，可能为ws,也可能为http
                if self.network == 'http':
                    self.network = 'tcp'
                    self.type = 'http'

                ws_opts = proxy_node.get('ws-opts')
                if ws_opts:
                    self.path = ws_opts.get('path')

                    headers = ws_opts.get('headers')
                    if headers:
                        self.host = headers.get('Host')

                http_opts = proxy_node.get('http-opts')
                if http_opts:
                    paths = http_opts.get('path')
                    if paths and isinstance(paths, list) and len(paths) > 0:
                        self.path = paths[0]
                        if len(paths) > 1:
                            logger.warning(f'节点：{proxy_node}，path多个->{paths}')

                    headers = http_opts.get('headers')
                    if headers:
                        Host = headers.get('Host')
                        if Host and isinstance(Host, list):
                            self.host = Host[0]
                            if len(Host) > 1:
                                logger.warning(f'节点：{proxy_node}，headers:Host多个->{paths}')
            elif self.protocol == 'trojan':
                self.password = proxy_node.get('password', '')
                self.network = proxy_node.get('network', '')
                self.sni = proxy_node.get('sni', '')
                self.udp = proxy_node.get('udp', '')
                self.skip_cert_verify = proxy_node.get('skip-cert-verify')

                ws_opts = proxy_node.get('ws-opts')
                if ws_opts:
                    self.path = ws_opts.get('path')

                    headers = ws_opts.get('headers')
                    if headers:
                        self.host = headers.get('Host')
            elif self.protocol == 'ssr':
                self.security = proxy_node.get('cipher', '')
                self.password = proxy_node.get('password', '')
                self.clash_ssr_obfs = proxy_node.get('obfs', '')
                self.clash_ssr_protocol = proxy_node.get('protocol', '')
                self.clash_ssr_obfs_param = proxy_node.get('obfs-param')
                self.clash_ssr_protocol_param = proxy_node.get('protocol-param')
                self.udp = proxy_node.get('udp')

        if self.address:
            self.name = self.name.strip()
            return True
        else:
            logger.warning(f'无法识别节点: {proxy_node}')
            return False

    def generate_v2rayn_link(self):
        if self.protocol == 'vmess':
            v2_data = {
                "v": self.v,
                "ps": self.name,
                "add": self.address,
                "port": self.port,
                "id": self.uuid,
                "aid": self.alter_id,
                "scy": self.security or 'auto',
                "net": self.network,
                "type": self.type or 'none',
                "host": self.host,
                "path": self.path or '/',
                "tls": 'tls' if self.tls else '',
                "sni": self.sni
            }
            return self.protocol + "://" + base64_encode(json.dumps(v2_data, ensure_ascii=False))
        elif self.protocol == 'ss':
            proxy = f'{self.encryption}:{self.password}@{self.address}:{self.port}'
            return self.protocol + '://' + base64_encode(proxy) + f'#{self.name}'
        elif self.protocol == 'trojan':
            params = []
            if self.peer:
                params.append(f'peer={self.peer}')
            if self.security:
                params.append(f'security={self.security}')
            if self.encryption:
                params.append(f'encryption={self.encryption}')
            if self.network:
                params.append(f'type={self.network}')
            if self.flow:
                params.append(f'flow={self.flow}')
            if self.sni:
                params.append(f'sni={self.sni}')
            if self.type:
                params.append(f'headerType={self.type}')
            if self.host:
                params.append(f'host={self.host}')
            if self.alpn:
                params.append(f'alpn={urllib.parse.quote_plus(self.alpn)}')
            if self.skip_cert_verify is False:  # true时未知????
                params.append('allowInsecure=1')

            proxy = f'{self.password}@{self.address}:{self.port}'
            if params:
                proxy = f'{proxy}?{"&".join(params)}'
            return self.protocol + '://' + proxy + f'#{self.name}'
        elif self.protocol == 'vless':
            params = []
            # self.path参数？
            if self.encryption:
                params.append(f'encryption={self.encryption}')
            if self.network:
                params.append(f'type={self.network}')
            if self.flow:
                params.append(f'flow={self.flow}')
            if self.sni:
                params.append(f'sni={self.sni}')
            if self.type:
                params.append(f'headerType={self.type}')
            if self.host:
                params.append(f'host={self.host}')
            if self.alpn:
                params.append(f'alpn={urllib.parse.quote_plus(self.alpn)}')
            if self.tls:
                params.append('security=tls')

            proxy = f'{self.uuid}@{self.address}:{self.port}'
            if params:
                proxy = f'{proxy}?{"&".join(params)}'
            return self.protocol + '://' + proxy + f'#{self.name}'
        else:
            logger.warning(f'v2rayN暂不支持该协议：{self.protocol}')
            return False

    def generate_surfboard_proxy(self):
        # https://getsurfboard.com/docs/profile-format/proxy/
        surfboard_proxy = f'{self.protocol}, {self.address}, {self.port}'

        if self.skip_cert_verify is True:
            skip_cert_verify = f', skip-cert-verify=true'
        elif self.skip_cert_verify is False:
            skip_cert_verify = f', skip-cert-verify=false'
        else:
            skip_cert_verify = ''

        sni = f', sni={self.sni}' if self.sni else ''

        if self.udp is True:
            udp_relay = f', udp-relay=true'
        elif self.udp is False:
            udp_relay = f', udp-relay=false'
        else:
            udp_relay = ''

        if self.protocol == 'ss':
            surfboard_proxy = f'{surfboard_proxy}, encrypt-method={self.encryption}, password={self.password}{udp_relay}'
        elif self.protocol == 'trojan':
            surfboard_proxy = f'{surfboard_proxy}, password={self.password}{udp_relay}{skip_cert_verify}{sni}'
        elif self.protocol == 'vmess':
            ws = ', ws=true' if self.network == 'ws' else ''

            if self.tls is True:
                tls = ', tls=true'
            elif self.tls is False:
                tls = ', tls=false'
            else:
                tls = ''

            ws_path = f', ws-path={self.path}' if self.path else ''
            ws_headers = f', ws-headers=Host:{self.host}' if self.host else ''
            vmess_aead = ', vmess-aead=true' if (self.alter_id and str(self.alter_id).strip() == '0') else ''

            surfboard_proxy = f'{surfboard_proxy}, username={self.uuid}{udp_relay}{ws}{tls}{ws_path}{ws_headers}{skip_cert_verify}{sni}{vmess_aead}'
        else:
            logger.warning(f'surfboard暂不支持该协议：{self.protocol}')
            return False

        return self.name, surfboard_proxy

    def generate_clash_proxy(self):
        clash_proxy = {
            "name": self.name,
            "type": self.protocol,
            "server": self.address,
            "port": int(self.port)
        }

        if self.protocol == 'vmess':
            extra_data = {
                "uuid": self.uuid,
                "alterId": int(self.alter_id),
                "cipher": self.security or 'auto',

                # ws
                "tls": self.tls,
                "skip-cert-verify": self.skip_cert_verify,
                "servername": self.sni,  # priority over wss host

                # common
                "udp": self.udp,
                "network": self.network
            }

            if self.network == 'ws':
                extra_data['ws-opts'] = {
                    "path": self.path or '/',
                    "headers": {
                        "Host": self.host
                    }
                }
            elif self.network == 'tcp':
                extra_data['network'] = 'http'
                extra_data['http-opts'] = {
                    "headers": {
                        "Host": self.host.split(',')
                    }
                }
        elif self.protocol == 'ss':
            extra_data = {
                'cipher': self.security,
                'password': self.password,
                'udp': self.udp
            }
        elif self.protocol == 'trojan':
            extra_data = {
                'password': self.password,
                'udp': self.udp,
                'sni': self.sni,
                'skip-cert-verify': self.skip_cert_verify,
                'network': self.network
            }

            if self.network == 'ws':
                extra_data['ws-opts'] = {
                    'path': self.path,
                    'headers': {
                        'Host': self.host
                    }
                }
        elif self.protocol == 'ssr':
            extra_data = {
                'cipher': self.security,
                'password': self.password,
                'obfs': self.clash_ssr_obfs,
                'protocol': self.clash_ssr_protocol,
                'obfs-param': self.clash_ssr_obfs_param,
                'protocol-param': self.clash_ssr_protocol_param,
                'udp': self.udp
            }
        else:
            logger.warning(f'clash暂不支持该协议：{self.protocol}')
            return False

        if extra_data:
            clash_proxy.update(extra_data)
            clash_proxy = dict([i for i in clash_proxy.items() if i[1] is not None])
            return clash_proxy

    def generate_leaf_proxy(self):
        leaf_proxy = f'{self.protocol}, {self.address}, {self.port}'

        if self.protocol == 'ss':
            leaf_proxy = f'{leaf_proxy}, encrypt-method={self.encryption}, password={self.password}'
        elif self.protocol == 'trojan':
            sni = f', sni={self.sni}' if self.sni else ''
            ws = ', ws=true' if self.network == 'ws' else ''
            ws_path = f', ws-path={self.path}' if self.path else ''

            leaf_proxy = f'{leaf_proxy}, password={self.password}{sni}{ws}{ws_path}'
        elif self.protocol == 'vmess':
            ws = ', ws=true' if self.network == 'ws' else ''
            ws_path = f', ws-path={self.path}' if self.path else ''
            tls = ', tls=true' if self.tls else ''
            # tls-cert???
            leaf_proxy = f'{leaf_proxy}, username={self.uuid}{ws}{ws_path}{tls}'
        else:
            logger.warning(f'leaf暂不支持该协议：{self.protocol}')
            return False

        return self.name, leaf_proxy

    def __str__(self):
        return os.linesep.join([f'{i[0]}={i[1]}' for i in vars(self).items() if i[1]])


if __name__ == '__main__':
    p = ProxyNode()
    # p.load('ssr://MTgzLjIzMi41Ni4xODI6MTI1NDphdXRoX2FlczEyOF9tZDU6Y2hhY2hhMjAtaWV0ZjpwbGFpbjpiWFJpZGpodS8_cmVtYXJrcz1TbUZ3WVc0JnByb3RvcGFyYW09TVRFME9EZ3lPa3gzWkZsTWFnJm9iZnNwYXJhbT1kQzV0WlM5MmNHNW9ZWFE')
    # p.load('trojan://sharecentre@sg.sharecentrepro.tk:443#SG')
    # p.load('trojan://sharecentretest@gy.sharecentrepro.tk:11451?peer=usd.scsevers.cf#%E7%BE%8E%E5%9B%BD%EF%BD%9CShareCentre')
    # p.load('vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIkF6dXJlIOaXpeacrCB8IDJjbS5nYXkg5YWs55uK6IqC54K5IiwNCiAgImFkZCI6ICJzaC5jdS4wMS4yMTExMjkueHl6IiwNCiAgInBvcnQiOiAiMzIxMjMiLA0KICAiaWQiOiAiMDBlZjM4NTMtN2NmYy00ZDc0LWE0NzgtODUwNjBlNGE5ZjhiIiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ3cyIsDQogICJ0eXBlIjogIm5vbmUiLA0KICAiaG9zdCI6ICIiLA0KICAicGF0aCI6ICIvIiwNCiAgInRscyI6ICIiLA0KICAic25pIjogIiIsDQogICJhbHBuIjogIiINCn0=')
    # p.load('ss://YWVzLTI1Ni1nY206MTE0NTE0@173.82.232.224:56634#%E6%B5%8B%E8%AF%95')
    # p.load('ss://YWVzLTI1Ni1nY206WTZSOXBBdHZ4eHptR0NAMTcyLjk5LjE5MC4zNTozMzA2#🇺🇸US_1950')
    # print(p)
    node = "trojan://e37c6d7efa845d60@116.129.253.191:3389/?sni=116.129.253.191#%F0%9F%87%A8%F0%9F%87%B3%20%E3%80%90tg%40freevpn8%E3%80%91_%F0%9F%87%A8%F0%9F%87%B3CN-%F0%9F%87%B9%F0%9F%87%BCTW_562"
    node = "trojan://5y8y3CwxRVYhyfSY@ce.rutracker-cn.com:443?security=xtls&encryption=none&type=tcp&flow=xtls-rprx-direct&sni=ce.rutracker-cn.com#v2cross.com"
    node = "trojan://password@104.16.124.42:443?flow=xtls-rprx-origin&security=tls&sni=host.com&alpn=http%2F1.1&type=tcp&headerType=http&host=host.com#name"
    node = "trojan://password@104.16.124.42:443/?flow=xtls-rprx-origin&security=tls&sni=host.com&alpn=h2%2Chttp%2F1.1&type=tcp&headerType=http&host=host.com#name"
    node = "vless://eb0f552d-c314-491a-b5e1-f0ee78cd7af6@220.32.41.124:443?encryption=none&flow=xtls-rprx-direct&security=tls&sni=vless.com&alpn=h2%2Chttp%2F1.1&type=ws&host=vless.com&path=%2Fvless.path#vless_name"
    node = "vless://eb0f552d-c314-491a-b5e1-f0ee78cd7af6@220.32.41.124:443?encryption=none&flow=xtls-rprx-direct&security=tls&sni=vless.com&alpn=h2%2Chttp%2F1.1&type=tcp&headerType=http&host=vless.com#vless_name"
    node = {'name': 'HK_2702_12.40Mb', 'server': 'yyyy.wwwbhjy.com', 'port': 2443, 'type': 'vmess',
            'uuid': 'dee32eb7-e190-4c6f-dd27-aa9c82cd5490', 'alterId': 0, 'cipher': 'auto', 'tls': True,
            'skip-cert-verify': True, 'network': 'ws', 'ws-opts': {'path': '/8a76fb13/', 'headers': {
            'Host': '%7B%22HOST%22:%22yyyy.wwwbhjy.com%22,%22Host%22:%22yyyy.wwwbhjy.com%22%7D'}}, 'udp': True}
    p.load(node)
    print(p)
    print(p.generate_surfboard_proxy())
