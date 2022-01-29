import configparser
import os
import re
from io import StringIO
from typing import Union, List

import yaml
from loguru import logger

from core.config_model import ProxyNode
from core.helper import base64_encode, remove_special_characters, base64_decode


def v2sub_2_nodelist(sub_content):
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
        vn = ProxyNode()
        logger.debug('检查v2节点有效性')
        if vn.load(link):
            logger.debug(f'订阅中的v2节点: {link}')
            nodes.append(vn)

    return nodes


def clashsub_2_nodelist(sub_content):
    dict_clash_content = {}
    try:
        dict_clash_content = yaml.load(sub_content, Loader=yaml.FullLoader)
    except Exception as e:
        logger.error(f'yaml解析失败: {e}')
    proxies = dict_clash_content.get("proxies", None)
    proxy_providers = dict_clash_content.get("proxy-providers", None)

    nodes = []
    if proxies:
        logger.debug(f'直接获取clash中的proxies：{proxies}')
        for proxy in proxies:
            c = ProxyNode()
            logger.debug('检查Clash节点有效性')
            if c.load(proxy):
                logger.debug(f"clash proxies中的节点: {c}")
                nodes.append(c)

    elif proxy_providers:
        logger.info(f'获取clash中的proxy-providers')
        for k, v in proxy_providers.items():
            provider_url = v["url"]
            provider_nodes = sub_2_nodelist(provider_url)
            logger.info(f"proxy-providers[{k}]节点个数: {len(provider_nodes)}")
            nodes.extend(provider_nodes)
    return nodes


def sub_2_nodelist(sub_content):
    sub_content = remove_special_characters(sub_content)

    if "rules:" in sub_content or sub_content.startswith("proxies:"):
        logger.info("该订阅为clash订阅")
        nodes = clashsub_2_nodelist(sub_content)
        logger.info(f"clash订阅内容中有效节点个数：{len(nodes)}")
    else:
        logger.info("该订阅为v2订阅")
        nodes = v2sub_2_nodelist(sub_content)
        logger.info(f"v2订阅内容中有效节点个数：{len(nodes)}")
    return nodes


def change_host(nodes: Union[ProxyNode, List[ProxyNode]], host: str):
    if isinstance(nodes, ProxyNode):
        nodes = [nodes]

    for node in nodes:
        node.change_host(host)


def generate_sub(nodes: Union[ProxyNode, List[ProxyNode]], client: str) -> str:
    if isinstance(nodes, ProxyNode):
        nodes = [nodes]

    sub = ""
    if client == "v2rayN":
        vn_links = []
        for node in nodes:
            proxy = node.generate_v2rayn_link()
            logger.debug(f'生成v2节点: {proxy}')
            vn_links.append(proxy)
        sub = base64_encode(os.linesep.join(vn_links))
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
            logger.debug(f'生成clash 节点: {proxy}')

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
                logger.debug(f'生成Surfboard 节点: {sf_proxy}')
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
                logger.debug(f'生成Leaf 节点: {leaf_proxy}')
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


def load_resources():
    # 从secrets加载
    links_str = os.environ.get('LINKS')
    if links_str:
        logger.info('加载节点或者订阅：secrets')
        return list(filter(lambda x: x.strip() != "", re.split('\r\n|\r|\n', links_str.strip())))

    # 从文件加载
    with open('./resources.txt', 'r') as f:
        logger.info('加载节点或者订阅：resources.txt')
        return list(filter(lambda x: x.strip() != "", [i.strip() for i in f.readlines()]))


def save_conf(conf, dir_, filename):
    if not os.path.exists(dir_):
        os.mkdir(dir_)

    with open(f'./{dir_}/{filename}', 'w') as f:
        f.write(conf)
