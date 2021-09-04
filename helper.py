import base64
import json
import os

import requests
from netaddr import IPAddress


def base64_decode(content):
    content = content.strip().replace(os.linesep, '').replace('\r', '').replace('\n', '').replace(' ', '')

    content_length = len(content)
    if content_length % 4 != 0:
        content = content.ljust(content_length + 4 - content_length % 4, "=")

    return str(base64.b64decode(content), "utf-8").strip()


def base64_encode(content):
    bytes_content = content.encode(encoding='utf-8')
    return base64.b64encode(bytes_content).decode('utf-8')


def is_base64_link(link):
    parts = link.strip().split('://')

    result = False
    if len(parts) == 2:
        try:
            json.loads(base64_decode(parts[1]))
            result = True
        except Exception:
            pass
    return result


def is_reserve_proxy(content):
    if not content:
        return False

    result = False
    if isinstance(content, str):
        if content.startswith('vmess://'):
            result = True
    elif isinstance(content, dict):
        protocol = content.get('type', "").strip()
        if protocol == 'vmess':
            result = True

    return result


def check_ip(ip):
    ip = ip.strip()
    result = True

    if ip == "1.1.1.1" or ip == "1.0.0.1" or ip == "0.0.0.0":
        return False

    try:
        ip_add = IPAddress(ip)
        if not ip_add.is_unicast() or ip_add.is_private() or ip_add.is_loopback() or ip_add.is_link_local() or ip_add.is_reserved():
            result = False
    except:
        pass

    return result


_request = None


def get_request(enable_proxy=False):
    global _request
    if _request:
        return _request
    else:
        def inner(url):
            proxies = None
            if enable_proxy:
                proxies = {
                    "http": "http://localhost:7891",
                    'https': 'https://localhost:7891'
                }

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36'}
            res = requests.get(url, headers=headers, proxies=proxies, verify=False)
            sub_content = res.text.strip()

            return sub_content

        _request = inner
        return _request


def remove_special_characters(content):
    return bytes(content, "ascii", "ignore").decode()


if __name__ == '__main__':
    print(is_base64_link(
        'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogIvCfh7fwn4e6IOS/hOe9l+aWryIsDQogICJhZGQiOiAiNDYuMjkuMTY1LjE0NSIsDQogICJwb3J0IjogIjgwIiwNCiAgImlkIjogImI1ODU3YWQ3LWUyNGMtNGUxZi1hOTYyLTkzZjQ3YmJlNTg3MyIsDQogICJhaWQiOiAiMSIsDQogICJzY3kiOiAiYXV0byIsDQogICJuZXQiOiAid3MiLA0KICAidHlwZSI6ICJub25lIiwNCiAgImhvc3QiOiAiYS4xODkuY24iLA0KICAicGF0aCI6ICIvIiwNCiAgInRscyI6ICJ0bHMiLA0KICAic25pIjogImEuMTg5LmNuIg0KfQ=='))
