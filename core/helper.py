import base64
import ipaddress
import os

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def base64_decode(content):
    content = content.strip().replace(os.linesep, '').replace('\r', '').replace('\n', '').replace(' ', '')

    content_length = len(content)
    if content_length % 4 != 0:
        content = content.ljust(content_length + 4 - content_length % 4, "=")

    return str(base64.b64decode(content), "utf-8").strip()


def base64_encode(content):
    bytes_content = content.encode(encoding='utf-8')
    return base64.b64encode(bytes_content).decode('utf-8')


def check_ip(ip):
    if ip == "1.1.1.1" or ip == "1.0.0.1" or ip == "0.0.0.0":
        return False

    try:
        ip_addr = ipaddress.ip_address(ip)
        if ip_addr.is_multicast or ip_addr.is_private or ip_addr.is_loopback or ip_addr.is_link_local or ip_addr.is_reserved or ip_addr.is_unspecified:
            return False
    except ValueError as e:
        if '.' not in ip:
            return False

    return True


_request = None


def get_request(enable_proxy=False, proxies_=None):
    global _request
    if _request:
        return _request
    else:
        def inner(url):
            proxies = None
            if enable_proxy:
                if proxies_:
                    proxies = proxies_
                else:
                    proxies = {
                        "http": "http://127.0.0.1:7890",
                        'https': 'http://127.0.0.1:7890'
                    }

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36'}
            res = requests.get(url, headers=headers, proxies=proxies, verify=False, timeout=3)
            sub_content = res.text.strip()

            return sub_content

        _request = inner
        return _request


def remove_special_characters(content):
    return bytes(content, "ascii", "ignore").decode()


if __name__ == '__main__':
    pass
