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
from core.converter import change_host, generate_sub, sub_2_nodelist
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
    "Surfboard",
    "v2rayN"
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
                    nodes.extend(node_list)
            else:
                vn = ProxyNode()
                logger.debug('检查v2节点有效性')
                if vn.load(i):
                    logger.info(f"v2节点，直接添加: {i}")
                    nodes.append(vn)
    return nodes


@app.get("/sub")
def sub(url: str, host: str, client: str):
    logger.debug(f"用户需要转换的内容：{url}")
    node_content = url.strip().replace(' ', "")
    node_content = unquote(node_content)
    input_list = re.split('\\|', node_content)

    nodes = resolve_proxies(input_list)

    logger.info(f"用户输入有效节点总个数为: {len(nodes)}")

    conf = ""
    if nodes:
        logger.info(f"将过滤完的节点的host用{host}替换")
        change_host(nodes, host)

        logger.info(f'开始生成{client}订阅')
        conf = generate_sub(nodes, client)

    return PlainTextResponse(conf, headers={'Content-Disposition': 'filename=ml-sub'})


@app.get("/")
def index(req: Request):
    data = {
        "request": req,
        "clients": clients
    }
    return template.TemplateResponse('index.html', data)
