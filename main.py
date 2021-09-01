import base64
import json
import os
import re
import sys

import requests
import yaml
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from loguru import logger
from netaddr import *

logger.remove()
logger.add(sys.stdout, level="INFO")

# app = Flask(__name__)
app = FastAPI()

reserve_protocol = ["vmess"]


def check_ip(ip):
    if type(ip) == str:
        ip = ip.strip()

    if ip == "1.1.1.1" or ip == "1.0.0.1" or ip == "0.0.0.0":
        return False

    try:
        ip_add = IPAddress(ip)
    except Exception:
        return False

    if ip_add.is_unicast() and not ip_add.is_private() and not ip_add.is_loopback() and not ip_add.is_link_local() and not ip_add.is_reserved():
        return True
    return False


def v2sub_2_list1(sub_content, host):
    logger.debug(f"原始订阅内容类型：{type(sub_content)}")
    logger.debug(f"订阅内容{sub_content}")
    dict_sub = yaml.load(sub_content, Loader=yaml.FullLoader)
    logger.debug(f"yaml转化为python对象：{dict_sub}")

    dict_sub["port"] = "7890"
    dict_sub["socks-port"] = 7891
    dict_sub["allow-lan"] = True
    dict_sub["mode"] = "global"
    dict_sub["log-level"] = "debug"
    dict_sub["external-controller"] = "127.0.0.1:9090"
    dict_sub["proxy-groups"] = [{"name": "proxy", "type": "select", "proxies": []}]
    dict_sub["rules"] = ["MATCH,proxy"]

    proxies = dict_sub['proxies']
    for node in proxies:
        logger.debug(f"{node}")

        if node.get('type') in reserve_protocol:
            network = node.get("network")
            if network == 'ws':
                node["ws-headers"] = {'Host': host}
            if network == None or network == "http":
                node["network"] = "http"
                node["http-opts"] = {"headers": {"host": host}}

    return yaml.dump(dict_sub).encode('utf-8')


def get_sub(url):
    proxies = {
        "http": "socks5://127.0.0.1:7890",
        'https': 'socks5://127.0.0.1:7890'
    }
    proxies = None
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36'}
    res = requests.get(url, headers=headers, proxies=proxies, verify=False)
    # res = requests.get(url, headers=headers, proxies=proxies)
    sub_content = res.text.strip()

    return sub_content


def base64_decode(content):
    content = content.strip().replace(os.linesep, '').replace('\r', '').replace('\n', '').replace(' ', '')

    content_length = len(content)
    if content_length % 4 != 0:
        content = content.ljust(content_length + 4 - content_length % 4, "=")

    return str(base64.b64decode(content), "utf-8").strip()


def base64_encode(content):
    bytes_content = content.encode(encoding='utf-8')
    return base64.b64encode(bytes_content).decode('utf-8')


def v2sub_2_nodelist(sub_content):
    origin_sub = base64_decode(sub_content)
    logger.debug(f"base64解码后订阅：{origin_sub}")
    nodes = re.split('\r\n|\n|\r', origin_sub)

    nodes_ = []
    for node in nodes:
        node = node.strip()
        if node:
            protocol, b64_info = node.split("://")
            nodes_.append((protocol, b64_info))

    return nodes_
    # new_nodes = []
    # for node in nodes:
    #     if node.strip() == "": continue
    #
    #     protocol, encoded_content = node.split("://")
    #
    #     if protocol in reserve_protocol:
    #         json_node = json.loads(base64.b64decode(encoded_content))
    #         logger.debug(f"base64解码后节点内容：{json_node}")
    #
    #         if not check_ip(json_node.get("add")): continue
    #
    #         if "ws" == json_node.get("net") or ("http" == json_node.get("type") and "tcp" == json_node.get("net")):
    #             logger.debug(f"原始host：{json_node['host']}")
    #             json_node["host"] = host
    #             logger.debug(f"替换host后节点内容：{json_node}")
    #
    #             new_node = protocol + "://" + base64.b64encode(bytes(json.dumps(json_node), encoding="UTF_8")).decode()
    #             new_nodes.append(new_node)
    #
    # logger.debug(f"替换host后符合协议的全部节点：{new_nodes}")
    # return base64.b64encode('\r\n'.join(new_nodes).encode())


def clashsub_2_nodelist(sub_content):
    dict_clash_content = yaml.load(sub_content, Loader=yaml.FullLoader)
    proxies = dict_clash_content.get("proxies", None)
    proxy_providers = dict_clash_content.get("proxy-providers", None)

    nodes = []
    if proxies:
        logger.debug(f'直接获取clash中的proxies：{proxies}')
        for proxy in proxies:
            logger.debug(f'clash>proxies>proxy: {proxy}')

            network = proxy.get("network", "")
            v2rayN_vmess_config = {
                "v": "2",
                "ps": proxy["name"],
                "add": proxy["server"],
                "port": proxy["port"],
                "id": proxy.get("uuid", ""),
                "aid": proxy.get("alterId", ""),
                "scy": proxy.get("cipher"),
                "net": network,  # tcp\kcp\ws\h2\quic
                "type": "none",  # (none\http\srtp\utp\wechat-video) *tcp or kcp or QUIC

                "host": "",
                # 1)http(tcp)->host中间逗号(,)隔开
                # 2)ws->host
                # 3)h2->host
                # 4)QUIC->securty

                "path": "/",
                # 1)ws->path
                # 2)h2->path
                # 3)QUIC->key/Kcp->seed
                # 4)grpc->serviceName

                "tls": "",  # tls
                "sni": ""

                # "tls": "tls",
                # "sni": "www.ccc.com"
            }

            if network == "http" or network == "":  # 待商榷，关注：https://lancellc.gitbook.io/clash/clash-config-file/proxies/config-a-vmess-proxy
                v2rayN_vmess_config["net"] = "tcp"
                v2rayN_vmess_config["type"] = "http"

            ws_headers = proxy.get("ws-headers", None)
            host = ""
            if ws_headers:
                host = ws_headers.get("Host", "")
            v2rayN_vmess_config["host"] = host  # 待商榷

            v2rayN_vmess_config["path"] = proxy.get("ws-path", "")  # 待商榷

            tls = "tls" if proxy.get("tls", None) else ""
            v2rayN_vmess_config["tls"] = tls

            sni = proxy.get("sni", "")
            if not sni and tls:
                sni = host  # 待商榷
            v2rayN_vmess_config["sni"] = sni

            protocol = proxy["type"]
            # v2_node = protocol + "://" + base64.b64encode(
            #     bytes(json.dumps(v2rayN_vmess_config), encoding="UTF_8")).decode(
            #     encoding="utf-8")
            v2_node = (protocol, v2rayN_vmess_config)
            logger.debug(f"v2: {v2_node}")
            nodes.append(v2_node)

    elif proxy_providers:
        logger.info(f'获取clash中的proxy-providers')
        for k, v in proxy_providers.items():
            provider_url = v["url"]
            provider_nodes = sub_2_nodelist(provider_url)
            logger.info(f"proxy-providers[{k}]转换成v2样式节点list个数: {len(provider_nodes)}")
            nodes.extend(provider_nodes)
    return nodes


def sub_2_nodelist(sub_url):
    # 将所有订阅中每个节点转成如下类型
    # vmess://ewogICJ2IjogIjIi...

    logger.info(f"开始获取订阅{sub_url}的内容")
    sub_content = get_sub(sub_url)
    sub_content = sub_content.encode("ascii", "ignore")
    sub_content = sub_content.decode()
    logger.debug(f"获取订阅{sub_url}的内容为: {sub_content}")

    if "rules:" in sub_content or sub_content.startswith("proxies:"):
        logger.info("该订阅为clash订阅")
        nodes = clashsub_2_nodelist(sub_content)
        logger.info(f"clash订阅内容转换为v2样式list个数：{len(nodes)}")
    else:
        logger.info("该订阅为v2订阅")
        nodes = v2sub_2_nodelist(sub_content)
        logger.info(f"v2订阅内容转换为v2样式list个数：{len(nodes)}")
    return nodes


def filter_nodes(nodes):
    logger.info(f"过滤节点，要保留协议: {reserve_protocol}")
    new_nodes = []
    for node in nodes:
        protocol, _ = node
        logger.debug(f"当前节点协议: {protocol}")
        if protocol in reserve_protocol:
            new_nodes.append(node)
    return new_nodes


def change_host(nodes, host):
    logger.info(f"将过滤完的节点的host用{host}替换")
    final_v2_nodes = []
    for protocol, node_config in nodes:
        if not isinstance(node_config, dict):
            node_config = json.loads(base64_decode(node_config))

        node_config["host"] = host
        final_v2_node = protocol + "://" + base64_encode(json.dumps(node_config, ensure_ascii=False))
        final_v2_nodes.append(final_v2_node)
    return final_v2_nodes


def generate_sub(final_v2_nodes):
    return base64_encode(os.linesep.join(final_v2_nodes))


@app.get("/sub")
def sub(input_content: str, host: str, client: str):
    logger.debug(f"用户需要转换的内容：{input_content}")
    node_content = input_content.strip()
    input_list = re.split('\r\n|\n|\r|\\|', node_content)

    v2_list = []
    for i in input_list:
        i = i.strip()
        if i.startswith("http"):
            node_list = sub_2_nodelist(i)
            v2_list.extend(node_list)
            continue

        protocol, node_config = i.split("://")
        logger.info(f"v2节点，直接添加: {i}")
        v2_list.append((protocol, node_config))
    logger.info(f"用户输入节点总个数为: {len(v2_list)}")

    v2_list = filter_nodes(v2_list)
    logger.info(f"过滤完节点后剩余节点个数: {len(v2_list)}")

    final_v2_nodes = change_host(v2_list, host)

    sub = generate_sub(final_v2_nodes)
    return HTMLResponse(sub)


@app.get("/")
def index():
    return HTMLResponse("hello world")


if __name__ == '__main__':
    # v2_sub = "https://yyjsd.top/api/v1/client/subscribe?token=51a42767197ef3d7b3e16005531f4647"
    # v2_sub1 = "https://sub.ykmbbs.top/api/v1/client/subscribe?token=f785c02f0a945355476023e250d923f7"
    # clash_sub = "https://subcon.dlj.tf/sub?target=clash&new_name=true&url=https%3A%2F%2Fyyjsd.top%2Fapi%2Fv1%2Fclient%2Fsubscribe%3Ftoken%3D51a42767197ef3d7b3e16005531f4647&insert=false&config=https%3A%2F%2Fraw.githubusercontent.com%2FACL4SSR%2FACL4SSR%2Fmaster%2FClash%2Fconfig%2FACL4SSR_Online.ini"
    #
    # class_public_pool_sub = "https://cdn.jsdelivr.net/gh/gankang/MyConfig@main/clash/proxypool.yaml"
    # sub_2_nodelist(class_public_pool_sub)
    # app.run(host="127.0.0.1", port=8000)
    pass
