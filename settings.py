log_level = "DEBUG"  #"INFO"  #

enable_proxy = True if log_level == 'DEBUG' else False

proxies = {
    "http": "socks5://127.0.0.1:1086",
    'https': 'socks5://127.0.0.1:1086'
}
