import os
import re
from typing import Union, List

import yaml
from loguru import logger

from core.config_model import ProxyNode
from core.helper import base64_encode, base64_decode, check_and_rename


def _v2sub_2_nodelist(sub_content):
    try:
        origin_sub = base64_decode(sub_content)
    except:
        logger.error(f'v2订阅转码失败，查明！{sub_content}')
        return []

    logger.debug(f"base64解码后订阅：{origin_sub}")
    raw_links = re.split('\r\n|\n|\r', origin_sub)

    nodes = []
    for link in raw_links:
        link = link.strip()
        pn = ProxyNode()
        if pn.load(link):
            nodes.append(pn)

    return nodes


def _clashsub_2_nodelist(sub_content):
    dict_clash_content = {}
    try:
        dict_clash_content = yaml.load(sub_content, Loader=yaml.FullLoader)  # yaml中有类似@字符导致无法解析
    except Exception as e:
        logger.error(f'yaml解析失败: {e}')
    proxies = dict_clash_content.get("proxies", None)
    proxy_providers = dict_clash_content.get("proxy-providers", None)

    nodes = []
    if proxies:
        logger.debug(f'直接获取clash中的proxies：{proxies}')
        for proxy in proxies:
            pn = ProxyNode()
            if pn.load(proxy):
                nodes.append(pn)

    elif proxy_providers:
        logger.info(f'获取clash中的proxy-providers')
        for k, v in proxy_providers.items():
            provider_url = v["url"]
            provider_nodes = sub_2_nodelist(provider_url)
            logger.info(f"proxy-providers[{k}]节点个数: {len(provider_nodes)}")
            nodes.extend(provider_nodes)
    return nodes


def sub_2_nodelist(sub_content):
    # sub_content = remove_special_characters(sub_content)

    if "rules:" in sub_content or sub_content.startswith("proxies:"):
        logger.info("该订阅为clash订阅")
        nodes = _clashsub_2_nodelist(sub_content)
        # logger.info(f"clash订阅中节点个数：{len(nodes)}")
    else:
        logger.info("该订阅为v2订阅")
        nodes = _v2sub_2_nodelist(sub_content)
        # logger.info(f"v2订阅中节点个数：{len(nodes)}")
    return nodes


def change_host(nodes: Union[ProxyNode, List[ProxyNode]], host: str):
    if isinstance(nodes, ProxyNode):
        nodes = [nodes]

    for node in nodes:
        node.host = host


def generate_sub(nodes: Union[ProxyNode, List[ProxyNode]], client: str, ml: bool = False) -> str:
    if isinstance(nodes, ProxyNode):
        nodes = [nodes]

    if ml:
        tmp = []
        for i in nodes:
            if i.protocol == 'vmess' and (i.network == 'ws' or i.network == 'tcp'):
                tmp.append(i)
        nodes = tmp
        logger.info(f'可用免流节点个数：{len(nodes)}')

    nodes.sort(key=lambda x: x.protocol)

    sub = ""
    if client == "v2rayN":
        v2_links = []
        for node in nodes:
            proxy = node.generate_v2rayn_link()
            logger.debug(f'生成v2节点: {proxy}')
            if proxy:
                v2_links.append(proxy)
        sub = base64_encode(os.linesep.join(v2_links))
    elif client == "Clash":
        sub = {
            "port": 1087,
            "socks-port": 1086,
            # "mixed-port": 7890,
            "allow-lan": False,
            "mode": "Rule",
            "log-level": "silent",
            "external-controller": "127.0.0.1:9090",
            "dns": {
                "enable": True,
                "enhanced-mode": "fake-ip",
                "fake-ip-range": "198.18.0.1/16",
                "ipv6": False,
                "nameserver": [
                    "114.114.114.114",
                    "223.5.5.5",
                    "tls://13800000000.rubyfish.cn:853"
                ],
                "fallback": [
                    "https://cloudflare-dns.com/dns-query",
                    "https://dns.google/dns-query",
                    "https://1.1.1.1/dns-query",
                    "tls://8.8.8.8:853"
                ],
                "fallback-filter": {
                    "geoip": True,
                    "geoip-code": "CN",
                    "ipcidr": [
                        "240.0.0.0/4"
                    ]
                }
            },
            'proxies': [],
            "proxy-groups": [
                {"name": "🌐 Select",
                 "type": "select",
                 "proxies": ['♻ Auto']},
                {"name": "♻ Auto",
                 "type": "url-test",
                 "proxies": [],
                 "url": "http://www.gstatic.com/generate_204",
                 "interval": 600,
                 "lazy": True}
            ],
            "rule-providers": {
                "anti-AD": {
                    "type": "http",
                    "behavior": "domain",
                    "url": "https://anti-ad.net/clash.yaml",
                    "path": "./ruleset/anti-AD.yaml",
                    "interval": 86400
                },
                "reject": {
                    "type": "http",
                    "behavior": "domain",
                    "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
                    "path": "./ruleset/reject.yaml",
                    "interval": 86400
                },
                "icloud": {
                    "type": "http",
                    "behavior": "domain",
                    "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt",
                    "path": "./ruleset/icloud.yaml",
                    "interval": 86400
                },
                "apple": {
                    "type": "http",
                    "behavior": "domain",
                    "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt",
                    "path": "./ruleset/apple.yaml",
                    "interval": 86400
                },
                "google": {
                    "type": "http",
                    "behavior": "domain",
                    "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt",
                    "path": "./ruleset/google.yaml",
                    "interval": 86400
                },
                "proxy": {
                    "type": "http",
                    "behavior": "domain",
                    "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
                    "path": "./ruleset/proxy.yaml",
                    "interval": 86400
                },
                "direct": {
                    "type": "http",
                    "behavior": "domain",
                    "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
                    "path": "./ruleset/direct.yaml",
                    "interval": 86400
                },
                "private": {
                    "type": "http",
                    "behavior": "domain",
                    "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
                    "path": "./ruleset/private.yaml",
                    "interval": 86400
                },
                "tld-not-cn": {
                    "type": "http",
                    "behavior": "domain",
                    "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt",
                    "path": "./ruleset/tld-not-cn.yaml",
                    "interval": 86400
                },
                "telegramcidr": {
                    "type": "http",
                    "behavior": "ipcidr",
                    "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt",
                    "path": "./ruleset/telegramcidr.yaml",
                    "interval": 86400
                },
                "lancidr": {
                    "type": "http",
                    "behavior": "ipcidr",
                    "url": "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
                    "path": "./ruleset/lancidr.yaml",
                    "interval": 86400
                }
            },
            "rules": [
                "PROCESS-NAME,CloudflareST.exe,DIRECT",
                "PROCESS-NAME,CloudflareST,DIRECT",
                "RULE-SET,anti-AD,REJECT",
                "RULE-SET,private,DIRECT",
                "RULE-SET,reject,REJECT",
                "RULE-SET,icloud,DIRECT",
                "RULE-SET,apple,DIRECT",
                "RULE-SET,google,DIRECT",
                "RULE-SET,proxy,🌐 Select",
                "RULE-SET,tld-not-cn,🌐 Select",
                "RULE-SET,direct,DIRECT",
                "RULE-SET,telegramcidr,🌐 Select,no-resolve",
                "RULE-SET,lancidr,DIRECT,no-resolve",
                "GEOIP,CN,DIRECT",
                "MATCH,🌐 Select"
            ]
        }

        if ml:
            sub.pop('rule-providers')
            sub.update({
                'rules': ["MATCH,🌐 Select"]
            })

        proxies = sub['proxies']
        proxy_names = sub["proxy-groups"][0]["proxies"]
        auto_names = sub["proxy-groups"][1]["proxies"]

        proxy_nodes = []
        for node in nodes:
            proxy = node.generate_clash_proxy()
            logger.debug(f'生成clash节点: {proxy}')

            if proxy:
                name = check_and_rename(proxy_nodes, proxy["name"])
                proxy['name'] = name

                proxies.append(proxy)
                proxy_names.append(name)
                auto_names.append(name)

        sub = yaml.dump(sub)
    elif client == "Surfboard":
        sub_data = [
            '[General]',
            'dns-server = 8.8.8.8, 114.114.114.114',
            'skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local',
            'proxy-test-url = http://www.gstatic.com/generate_204',
            'http-listen = 0.0.0.0:1087',
            'socks5-listen = 0.0.0.0:1086',
            '[Proxy]'
        ]

        proxy_nodes = []
        proxy_name_list = []
        for node in nodes:
            proxy_node = node.generate_surfboard_proxy()
            if proxy_node:
                proxy_name, proxy_info = proxy_node
                logger.debug(f'生成Surfboard节点: {proxy_name} = {proxy_info}')

                name = check_and_rename(proxy_nodes, proxy_name)
                sub_data.append(f'{name} = {proxy_info}')
                proxy_name_list.append(name)

        names = ', '.join(proxy_name_list)

        sub_data.append('[Proxy Group]')
        select_group = f'Proxy = select, Auto, {names}'
        auto_group = f'Auto = url-test, {names}, url=http://www.gstatic.com/generate_204, interval=600, tolerance=100, timeout=5'
        sub_data.append(auto_group)
        sub_data.append(select_group)

        sub_data.append('[Rule]')
        if not ml:
            sub_data.append('RULE-SET, https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/ruleset/proxy.txt, Proxy')
            sub_data.append('RULE-SET, https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/ruleset/direct.txt, DIRECT')
            sub_data.append('RULE-SET, https://cdn.jsdelivr.net/gh/Loyalsoldier/surge-rules@release/ruleset/telegramcidr.txt, Proxy')
            sub_data.append('GEOIP, CN, DIRECT')
        sub_data.append('FINAL, Proxy')

        sub = os.linesep.join(sub_data)
    elif client == "Leaf":
        sub_data = [
            '[General]',
            'loglevel = info',
            'dns-server = 8.8.8.8, 114.114.114.114',
            'interface = 127.0.0.1',
            'port = 1087',
            'socks-interface = 127.0.0.1',
            'socks-port = 1086',
            '[Proxy]',
            'Direct = direct',
            'Reject = reject',
        ]

        proxy_nodes = []
        proxy_name_list = []
        for node in nodes:
            proxy_node = node.generate_leaf_proxy()
            if proxy_node:
                proxy_name, proxy_info = proxy_node
                logger.debug(f'生成Leaf节点: {proxy_name} = {proxy_info}')

                name = check_and_rename(proxy_nodes, proxy_name)
                sub_data.append(f'{name} = {proxy_info}')
                proxy_name_list.append(name)

        names = ', '.join(proxy_name_list)

        sub_data.append('[Proxy Group]')
        auto_group = f'Proxy = fallback, {names}, interval=600, timeout=5'
        sub_data.append(auto_group)

        sub_data.append('[Rule]')
        if not ml:
            sub_data.append('EXTERNAL, site:category-ads-all, Reject')
            sub_data.append('EXTERNAL, site:geolocation-!cn, Proxy')
            sub_data.append('EXTERNAL, site:cn, Direct')
            sub_data.append('GEOIP, CN, Direct')
        sub_data.append('FINAL, Proxy')

        sub = os.linesep.join(sub_data)

    return sub


if __name__ == '__main__':
    p = ProxyNode()
    p.load(
        'vmess://eyJhZGQiOiAiYTMzLnYyLmdheSIsICJ2IjogIjIiLCAicHMiOiAiXHU1MTczXHU2Y2U4XHU3NTM1XHU2MmE1aHR0cHM6Ly90Lm1lL2FpZmVueGlhbmcyMDIwIiwgInBvcnQiOiAzMzc5MiwgImlkIjogImU1NWNkMTgyLTAxYjAtNGZiNy1hNTEwLTM2MzcwMWE0OTFjNSIsICJhaWQiOiAiMCIsICJuZXQiOiAid3MiLCAidHlwZSI6ICIiLCAiaG9zdCI6ICJhMzMudjIuZ2F5IiwgInBhdGgiOiAiLyIsICJ0bHMiOiAiIn0=')
    p2 = ProxyNode()
    p2.load(
        'vmess://eyJhZGQiOiAiYTMzLnYyLmdheSIsICJ2IjogIjIiLCAicHMiOiAiXHU1MTczXHU2Y2U4XHU3NTM1XHU2MmE1aHR0cHM6Ly90Lm1lL2FpZmVueGlhbmcyMDIwIiwgInBvcnQiOiAzMzc5MiwgImlkIjogImU1NWNkMTgyLTAxYjAtNGZiNy1hNTEwLTM2MzcwMWE0OTFjNSIsICJhaWQiOiAiMCIsICJuZXQiOiAid3MiLCAidHlwZSI6ICIiLCAiaG9zdCI6ICJhMzMudjIuZ2F5IiwgInBhdGgiOiAiLyIsICJ0bHMiOiAiIn0=')

    c = generate_sub([p, p2], 'Clash', True)
    print(c)
