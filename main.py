import re
import sys
from typing import Union, List
from urllib.parse import unquote

from fastapi import FastAPI
from loguru import logger
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.templating import Jinja2Templates

import settings
from core.config_model import ProxyNode
from core.converter import change_host, sub_2_nodelist, generate_sub
from core.helper import get_request

# 设置日志
logger_level = settings.log_level
logger.remove()
logger.add(sys.stdout, level=logger_level)

request = get_request(settings.enable_proxy, settings.proxies)

app = FastAPI()
template = Jinja2Templates('templates')

clients = [
    "Clash",
    "v2rayN",
    "Leaf",
    "Surfboard"
]


def resolve_proxies(proxies: Union[str, List]) -> List:
    if isinstance(proxies, str):
        proxies = [proxies]

    nodes = []
    for i in proxies:
        if isinstance(i, str):
            i = i.strip()
            if i.startswith("http"):
                logger.info(f"开始获取订阅{i}的内容")
                try:
                    sub_content = request(i)
                    logger.debug(f"获取订阅的内容为: {sub_content}")
                except Exception as e:
                    logger.error(f"获取订阅内容出错: {e}")
                    continue

                if sub_content:
                    node_list = sub_2_nodelist(sub_content)
                    logger.info(f"订阅中节点个数：{len(node_list)}，来自订阅--> {i}")
                    nodes.extend(node_list)
            else:
                pn = ProxyNode()
                logger.info(f"v2节点，直接添加: {i}")
                if pn.load(i):
                    nodes.append(pn)
    return nodes


@app.get("/sub")
def sub(req: Request, url: str, host: str, client: str):
    print(req.url)
    logger.info(f"用户需要转换的内容：{url}")
    node_content = url.strip().replace(' ', "")
    node_content = unquote(node_content)
    input_list = re.split('\\|', node_content)

    nodes = resolve_proxies(input_list)

    logger.info(f"用户输入总节点个数为: {len(nodes)}")

    if nodes:
        if host:
            logger.info(f"将过滤完的节点的host用{host}替换")
            change_host(nodes, host)

            logger.info(f'开始生成免流{client}订阅')
            conf = generate_sub(nodes, client, True)

            if client == 'Surfboard':
                conf = f'#!MANAGED-CONFIG {req.url} interval=60 strict=true\r\n{conf}'
            return PlainTextResponse(conf,
                                     headers={'Content-Disposition': 'filename=subapi', 'profile-update-interval': "2"})
        else:
            logger.info(f'开始生成{client}订阅')
            conf = generate_sub(nodes, client)

            if client == 'Surfboard':
                conf = f'#!MANAGED-CONFIG {req.url} interval=60 strict=true\r\n{conf}'
            return PlainTextResponse(conf,
                                     headers={'Content-Disposition': 'filename=subapi', 'profile-update-interval': "2"})


@app.get("/")
def index(req: Request):
    data = {
        "request": req,
        "clients": clients
    }
    return template.TemplateResponse('index.html', data)
