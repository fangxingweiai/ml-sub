import configparser
import os
import re
import sys
from io import StringIO
from urllib.parse import unquote

import yaml
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from loguru import logger
from starlette.requests import Request
from starlette.templating import Jinja2Templates

from config_models import ProxyNode
from helper import base64_decode, base64_encode, get_request, remove_special_characters

# 设置日志
logger_level = "INFO"
logger.remove()
logger.add(sys.stdout, level=logger_level)
# 设置代理
enable_proxy = True if logger_level == "DEBUG" else False
get_sub = get_request(enable_proxy)

app = FastAPI()
template = Jinja2Templates('templates')


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
    sub_content = sub_content.replace('@', '')
    dict_clash_content = yaml.load(sub_content, Loader=yaml.FullLoader)
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


def sub_2_nodelist(sub_url):
    logger.info(f"开始获取订阅{sub_url}的内容")
    try:
        sub_content = get_sub(sub_url)
    except Exception as e:
        logger.error(f"获取订阅内容出错! {e.args}")
        return []

    sub_content = remove_special_characters(sub_content)
    logger.debug(f"获取订阅{sub_url}的内容为: {sub_content}")

    if "rules:" in sub_content or sub_content.startswith("proxies:"):
        logger.info("该订阅为clash订阅")
        nodes = clashsub_2_nodelist(sub_content)
        logger.info(f"clash订阅内容中有效节点个数：{len(nodes)}")
    else:
        logger.info("该订阅为v2订阅")
        nodes = v2sub_2_nodelist(sub_content)
        logger.info(f"v2订阅内容中有效节点个数：{len(nodes)}")
    return nodes


def change_host(nodes, host):
    logger.info(f"将过滤完的节点的host用{host}替换")
    for node in nodes:
        node.change_host(host)
        logger.debug(f'{type(node)} 替换完host: {node}')


def generate_sub(nodes, client):
    sub = ""
    if client == "v2rayN":
        vn_links = []
        for node in nodes:
            logger.debug(f'生成v2节点: {node}')
            vn_links.append(node.generate_v2rayn_link())
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
        sub.set("General", "proxy-test-url", "http://www.gstatic.com/generate_204")

        sub.add_section("Proxy")

        sub.add_section("Proxy Group")
        # sub.set('Proxy Group', 'Proxy', 'select,DIRECT,REJECT')
        select_proxy = 'select, auto, DIRECT, REJECT'
        # AutoTestGroup = url-test, ProxySOCKS5, ProxySOCKS5TLS, url=http://www.gstatic.com/generate_204, interval=600, tolerance=100, timeout=5
        auto_proxy = 'url-test'

        sub.add_section("Rule")
        sub.set('Rule', '', 'FINAL,select')

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
        sub.set('Proxy Group', 'select', select_proxy)
        sub.set('Proxy Group', 'auto', auto_proxy)

        with StringIO() as f:
            sub.write(f)
            s = f.getvalue()
            sub = re.sub(r'\s=\s+FINAL,select', "FINAL, select", s)
    return sub


clients = [
    "Clash",
    "Surfboard",
    "v2rayN"
]


@app.get("/sub")
def sub(url: str, host: str, client: str):
    logger.debug(f"用户需要转换的内容：{url}")
    node_content = url.strip().replace(' ', "")
    node_content = unquote(node_content)
    input_list = re.split('\\|', node_content)

    nodes = []
    for i in input_list:
        i = i.strip()
        if i.startswith("http"):
            node_list = sub_2_nodelist(i)
            nodes.extend(node_list)
        else:
            vn = ProxyNode()
            logger.debug('检查v2节点有效性')
            if vn.load(i):
                logger.info(f"v2节点，直接添加: {i}")
                nodes.append(vn)

    logger.info(f"用户输入有效节点总个数为: {len(nodes)}")

    sub = ""
    if len(nodes) > 0:
        change_host(nodes, host)

        logger.info(f'开始生成{client}订阅')
        sub = generate_sub(nodes, client)
        logger.info(f'生成{client}订阅成功！')

    return PlainTextResponse(sub, headers={'Content-Disposition': 'filename=ml-sub'})


@app.get("/")
def index(req: Request):
    data = {
        "request": req,
        "clients": clients
    }
    return template.TemplateResponse('index.html', data)
