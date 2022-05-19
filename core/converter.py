import configparser
import json
import os
import re
from io import StringIO
from typing import Union, List

import requests
import yaml
from loguru import logger

from core.config_model import ProxyNode
from core.helper import base64_encode, remove_special_characters, base64_decode
import urllib.request


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


def generate_ml_sub(nodes: Union[ProxyNode, List[ProxyNode]], client: str) -> str:
    if isinstance(nodes, ProxyNode):
        nodes = [nodes]

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
            "port": 7891,
            "socks-port": 7890,
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
                 "proxies": ['♻ Auto', 'DIRECT', 'REJECT']},
                {"name": "♻ Auto",
                 "type": "url-test",
                 "proxies": [],
                 "url": "http://www.gstatic.com/generate_204",
                 "interval": 600,
                 "lazy": True}
            ],
            'rules': ["MATCH,🌐 Select"]
        }

        # clash中节点重名会运行不了，故直接用序号代替原来名字。解析clash原订阅时，订阅内容中包含一些特殊字符，通过处理也会导致节点名字不完整甚至名字完全丢失。
        proxy_name = 0

        proxies = sub['proxies']
        proxy_names = sub["proxy-groups"][0]["proxies"]
        auto_names = sub["proxy-groups"][1]["proxies"]
        for node in nodes:
            proxy = node.generate_clash_proxy()
            logger.debug(f'生成clash节点: {proxy}')
            if proxy:
                proxy_name += 1
                proxy_name_str = str(proxy_name)

                proxy["name"] = proxy_name_str
                proxies.append(proxy)
                proxy_names.append(proxy_name_str)
                auto_names.append(proxy_name_str)

        sub = yaml.dump(sub)
    elif client == "Surfboard":
        sub = configparser.ConfigParser()

        sub.add_section("General")
        sub.set("General", "dns-server", "system, 8.8.8.8, 8.8.4.4")
        sub.set("General", "skip-proxy",
                "127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local")
        sub.set("General", "proxy-test-url", "http://www.gstatic.com/generate_204")

        sub.add_section("Proxy")

        sub.add_section("Proxy Group")
        # sub.set('Proxy Group', 'Proxy', 'select,DIRECT,REJECT')
        select_proxy = 'select, auto'
        # AutoTestGroup = url-test, ProxySOCKS5, ProxySOCKS5TLS, url=http://www.gstatic.com/generate_204, interval=600, tolerance=100, timeout=5
        auto_proxy = 'url-test'

        sub.add_section("Rule")
        sub.set('Rule', '', 'FINAL,ml')

        # Surfboard中节点重名会运行不了，故直接用序号代替原来名字。解析Surfboard原订阅时，订阅内容中包含一些特殊字符，通过处理也会导致节点名字不完整甚至名字完全丢失。
        proxy_name = 0

        for node in nodes:
            sf_proxy = node.generate_surfboard_proxy()
            if sf_proxy:
                logger.debug(f'生成Surfboard节点: {sf_proxy[0]} = {sf_proxy[1]}')
                _, conf = sf_proxy

                proxy_name += 1
                proxy_name_str = str(proxy_name)

                sub.set('Proxy', proxy_name_str, conf)
                select_proxy = select_proxy + ', ' + proxy_name_str
                auto_proxy = auto_proxy + ', ' + proxy_name_str
        auto_proxy = auto_proxy + ', url=http://www.gstatic.com/generate_204, interval=600, tolerance=100, timeout=5'
        sub.set('Proxy Group', 'ml', select_proxy)
        sub.set('Proxy Group', 'auto', auto_proxy)

        with StringIO() as f:
            sub.write(f)
            s = f.getvalue()
            sub = re.sub(r'\s=\s+FINAL,ml', "FINAL, ml", s)
    elif client == "Leaf":
        sub = configparser.ConfigParser()

        sub.add_section("General")
        sub.set("General", "loglevel", "off")
        sub.set("General", "dns-server", "1.1.1.1, 8.8.8.8, 114.114.114.114, 223.5.5.5")
        # sub.set("General", "proxy-test-url", "http://www.gstatic.com/generate_204")
        sub.set("General", "interface", "127.0.0.1")
        sub.set("General", "port", "7891")
        sub.set("General", "socks-interface", "127.0.0.1")
        sub.set("General", "socks-port", "7890")

        sub.add_section("Proxy")

        sub.add_section("Proxy Group")
        # AutoTestGroup = url-test, ProxySOCKS5, ProxySOCKS5TLS, url=http://www.gstatic.com/generate_204, interval=600, tolerance=100, timeout=5
        fallback_group = 'fallback'

        sub.add_section("Rule")
        sub.set('Rule', '', 'FINAL,ml')

        # Surfboard中节点重名会运行不了，故直接用序号代替原来名字。解析Surfboard原订阅时，订阅内容中包含一些特殊字符，通过处理也会导致节点名字不完整甚至名字完全丢失。
        proxy_name = 0

        for node in nodes:
            leaf_proxy = node.generate_leaf_proxy()
            if leaf_proxy:
                logger.debug(f'生成Leaf节点: {leaf_proxy[0]} = {leaf_proxy[1]}')
                _, conf = leaf_proxy

                proxy_name += 1
                proxy_name_str = str(proxy_name)

                sub.set('Proxy', proxy_name_str, conf)

                fallback_group = fallback_group + ', ' + proxy_name_str
        fallback_group = fallback_group + ', interval=600, timeout=5'
        sub.set('Proxy Group', 'ml', fallback_group)

        with StringIO() as f:
            sub.write(f)
            s = f.getvalue()
            sub = re.sub(r'\s=\s+FINAL,ml', "FINAL, ml", s)
    return sub


def generate_sub(nodes: Union[ProxyNode, List[ProxyNode]], client: str) -> str:
    if isinstance(nodes, ProxyNode):
        nodes = [nodes]

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
            "mixed-port": 7890,
            "allow-lan": False,
            "mode": "Rule",
            "log-level": "silent",
            "external-controller": "127.0.0.1:9090",
            'proxies': [],
            "proxy-groups": [
                {"name": "🌐 Select",
                 "type": "select",
                 "proxies": ['♻ Auto', 'DIRECT', 'REJECT']},
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

        # clash中节点重名会运行不了，故直接用序号代替原来名字。解析clash原订阅时，订阅内容中包含一些特殊字符，通过处理也会导致节点名字不完整甚至名字完全丢失。
        proxy_name = 0

        proxies = sub['proxies']
        proxy_names = sub["proxy-groups"][0]["proxies"]
        auto_names = sub["proxy-groups"][1]["proxies"]
        for node in nodes:
            proxy = node.generate_clash_proxy()
            logger.debug(f'生成clash节点: {proxy}')

            if proxy:
                proxy_name += 1
                proxy_name_str = str(proxy_name)

                proxy["name"] = proxy_name_str
                proxies.append(proxy)
                proxy_names.append(proxy_name_str)
                auto_names.append(proxy_name_str)

        sub = yaml.dump(sub)
    elif client == "Surfboard":
        sub = configparser.ConfigParser()

        sub.add_section("General")
        sub.set("General", "dns-server", "system, 8.8.8.8, 8.8.4.4")
        sub.set("General", "skip-proxy",
                "127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local")
        sub.set("General", "proxy-test-url", "http://www.gstatic.com/generate_204")

        sub.add_section("Proxy")

        sub.add_section("Proxy Group")
        # sub.set('Proxy Group', 'Proxy', 'select,DIRECT,REJECT')
        select_proxy = 'select, auto'
        # AutoTestGroup = url-test, ProxySOCKS5, ProxySOCKS5TLS, url=http://www.gstatic.com/generate_204, interval=600, tolerance=100, timeout=5
        auto_proxy = 'url-test'

        sub.add_section("Rule")
        sub.set('Rule', 'cn', 'geoip,cn,direct')
        sub.set('Rule', 'proxy', 'FINAL,proxy')

        # Surfboard中节点重名会运行不了，故直接用序号代替原来名字。解析Surfboard原订阅时，订阅内容中包含一些特殊字符，通过处理也会导致节点名字不完整甚至名字完全丢失。
        proxy_name = 0

        for node in nodes:
            sf_proxy = node.generate_surfboard_proxy()
            if sf_proxy:
                logger.debug(f'生成Surfboard节点: {sf_proxy[0]} = {sf_proxy[1]}')
                _, conf = sf_proxy

                proxy_name += 1
                proxy_name_str = str(proxy_name)

                sub.set('Proxy', proxy_name_str, conf)
                select_proxy = select_proxy + ', ' + proxy_name_str
                auto_proxy = auto_proxy + ', ' + proxy_name_str
        auto_proxy = auto_proxy + ', url=http://www.gstatic.com/generate_204, interval=600, tolerance=100, timeout=5'
        sub.set('Proxy Group', 'proxies', select_proxy)
        sub.set('Proxy Group', 'auto', auto_proxy)

        with StringIO() as f:
            sub.write(f)
            s = f.getvalue()
            sub = re.sub(r'cn\s+=\s+geoip,cn,direct', "GEOIP,CN,DIRECT", s)
            sub = re.sub(r'proxy\s+=\s+FINAL,proxy', "FINAL,proxies", sub)
    elif client == "Leaf":
        sub = configparser.ConfigParser()

        sub.add_section("General")
        sub.set("General", "loglevel", "off")
        sub.set("General", "dns-server", "1.1.1.1, 8.8.8.8, 114.114.114.114, 223.5.5.5")
        # sub.set("General", "proxy-test-url", "http://www.gstatic.com/generate_204")
        sub.set("General", "interface", "127.0.0.1")
        sub.set("General", "port", "7891")
        sub.set("General", "socks-interface", "127.0.0.1")
        sub.set("General", "socks-port", "7890")

        sub.add_section("Proxy")
        sub.set('Proxy', 'direct', 'direct')
        sub.set('Proxy', 'reject', 'reject')

        sub.add_section("Proxy Group")
        # AutoTestGroup = url-test, ProxySOCKS5, ProxySOCKS5TLS, url=http://www.gstatic.com/generate_204, interval=600, tolerance=100, timeout=5
        fallback_group = 'fallback'

        sub.add_section("Rule")
        sub.set('Rule', 'cn1', 'EXTERNAL, site:category-ads-all, reject')
        sub.set('Rule', 'cn2', 'EXTERNAL, site:geolocation-!cn, proxy')
        sub.set('Rule', 'cn3', 'EXTERNAL, site:cn, direct')
        sub.set('Rule', 'cn4', 'GEOIP, cn, direct')
        sub.set('Rule', 'cn5', 'FINAL, proxy')

        # Surfboard中节点重名会运行不了，故直接用序号代替原来名字。解析Surfboard原订阅时，订阅内容中包含一些特殊字符，通过处理也会导致节点名字不完整甚至名字完全丢失。
        proxy_name = 0

        for node in nodes:
            leaf_proxy = node.generate_leaf_proxy()
            if leaf_proxy:
                print(leaf_proxy)
                logger.debug(f'生成Leaf节点: {leaf_proxy[0]} = {leaf_proxy[1]}')
                _, conf = leaf_proxy

                proxy_name += 1
                proxy_name_str = str(proxy_name)

                sub.set('Proxy', proxy_name_str, conf)

                fallback_group = fallback_group + ', ' + proxy_name_str
        fallback_group = fallback_group + ', interval=600, timeout=5'
        sub.set('Proxy Group', 'proxy', fallback_group)

        with StringIO() as f:
            sub.write(f)
            s = f.getvalue()
            sub = re.sub(r'cn1\s+=\s+EXTERNAL, site:category-ads-all, reject',
                         "EXTERNAL, site:category-ads-all, reject", s)
            sub = re.sub(r'cn2\s+=\s+EXTERNAL, site:geolocation-!cn, proxy', "EXTERNAL, site:geolocation-!cn, proxy",
                         sub)
            sub = re.sub(r'cn3\s+=\s+EXTERNAL, site:cn, direct', "EXTERNAL, site:cn, direct", sub)
            sub = re.sub(r'cn4\s+=\s+GEOIP, cn, direct', "GEOIP, cn, direct", sub)
            sub = re.sub(r'cn5\s+=\s+FINAL, proxy', "FINAL, proxy", sub)
    return sub


if __name__ == '__main__':
    p = ProxyNode()
    p.load(
        'vmess://eyJhZGQiOiAiYTMzLnYyLmdheSIsICJ2IjogIjIiLCAicHMiOiAiXHU1MTczXHU2Y2U4XHU3NTM1XHU2MmE1aHR0cHM6Ly90Lm1lL2FpZmVueGlhbmcyMDIwIiwgInBvcnQiOiAzMzc5MiwgImlkIjogImU1NWNkMTgyLTAxYjAtNGZiNy1hNTEwLTM2MzcwMWE0OTFjNSIsICJhaWQiOiAiMCIsICJuZXQiOiAid3MiLCAidHlwZSI6ICIiLCAiaG9zdCI6ICJhMzMudjIuZ2F5IiwgInBhdGgiOiAiLyIsICJ0bHMiOiAiIn0=')
    c = generate_sub(p, 'Leaf')
    print(c)
