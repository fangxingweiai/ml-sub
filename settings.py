log_level = "INFO"  #"DEBUG"  #

enable_proxy = True if log_level == 'DEBUG' else False

proxies = {
    "http": "http://127.0.0.1:7891",
    'https': 'http://127.0.0.1:7891'
}
