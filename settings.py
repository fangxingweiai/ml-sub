log_level = "INFO"  #"DEBUG"  #

enable_proxy = True if log_level == 'DEBUG' else False

proxies = {
    "http": "socks5://127.0.0.1:7890",
    'https': 'socks5://127.0.0.1:7890'
}
