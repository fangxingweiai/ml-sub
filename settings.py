log_level = "DEBUG" #"INFO"  #

enable_proxy = True if log_level == 'DEBUG' else False

proxies = {
    "http": "http://127.0.0.1:7891",
    'https': 'http://127.0.0.1:7891'
}

ml_host = 'wapsd.189.cn'
conf_dir = 'conf'
