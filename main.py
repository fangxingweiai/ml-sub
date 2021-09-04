import os
import re
import sys

import yaml
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from loguru import logger

from config_models import V2rayN, Clash
from helper import base64_decode, base64_encode, is_base64_link, get_request, is_reserve_proxy, \
    remove_special_characters

# 设置日志
logger_level = "DEBUG"
logger.remove()
logger.add(sys.stdout, level=logger_level)
# 设置代理
enable_proxy = True if logger_level == "DEBUG" else False
get_sub = get_request(enable_proxy)

app = FastAPI()


def v2sub_2_nodelist(sub_content):
    origin_sub = base64_decode(sub_content)
    logger.debug(f"base64解码后订阅：{origin_sub}")
    raw_links = re.split('\r\n|\n|\r', origin_sub)

    nodes = []
    for link in raw_links:
        link = link.strip()
        if is_reserve_proxy(link):
            if is_base64_link(link):
                vn = V2rayN()
                if vn.extract_from_base64_link(link):
                    logger.debug(f'订阅中的v2节点: {link}')
                    nodes.append(vn)
            else:
                logger.warning(f'该节点不是base64的v2节点: {link},查明！')
        else:
            logger.debug(f'无效的节点: {link}')
    return nodes


def clashsub_2_nodelist(sub_content):
    dict_clash_content = yaml.load(sub_content, Loader=yaml.FullLoader)
    proxies = dict_clash_content.get("proxies", None)
    proxy_providers = dict_clash_content.get("proxy-providers", None)

    nodes = []
    if proxies:
        logger.debug(f'直接获取clash中的proxies：{proxies}')
        for proxy in proxies:
            if is_reserve_proxy(proxy):
                c = Clash()
                if c.extract(proxy):
                    logger.debug(f"clash proxies中的节点: {c}")
                    nodes.append(c)
            else:
                logger.debug(f'无效的节点: {proxy}')

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
    except Exception:
        logger.error("获取订阅内容出错!")
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
        node.host = host
        logger.debug(f'{type(node)} 替换完host: {node}')


def generate_sub(nodes, client):
    sub = ""
    if client == "v2rayN":
        vn_links = []
        for node in nodes:
            vn_links.append(node.generate_v2rayn_link())
        sub = base64_encode(os.linesep.join(vn_links))
    return sub


@app.get("/sub")
def sub(input_content: str, host: str, client: str):
    logger.debug(f"用户需要转换的内容：{input_content}")
    node_content = input_content.strip()
    input_list = re.split('\r\n|\n|\r|\\|', node_content)

    nodes = []
    for i in input_list:
        i = i.strip()
        if i.startswith("http"):
            node_list = sub_2_nodelist(i)
            nodes.extend(node_list)
        elif is_reserve_proxy(i):
            if is_base64_link(i):
                vn = V2rayN()
                if vn.extract_from_base64_link(i):
                    logger.info(f"v2节点，直接添加: {i}")
                    nodes.append(vn)
            else:
                logger.warning(f'该节点不是base64的v2节点: {i},查明！')
        else:
            logger.debug(f'无效的节点: {i}')

    logger.info(f"用户输入有效节点总个数为: {len(nodes)}")

    sub = ""
    if len(nodes) > 0:
        change_host(nodes, host)

        logger.info(f'生成{client}订阅')
        sub = generate_sub(nodes, client)
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
    os.getenv("PORT")
