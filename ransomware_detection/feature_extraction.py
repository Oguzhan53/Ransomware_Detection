import pandas as pd

import re

from urllib.parse import urlparse
from tld import get_tld
from ipwhois import IPWhois
import pydnsbl
import socket

from math import log


def check_blacklist(url):
    try:
        domain_checker = pydnsbl.DNSBLDomainChecker()
        bc = domain_checker.check(url)
        return bc.blacklisted
    except:
        return False


def add_result(type):
    try:
        if type.lower() == "benign":
            return 0
        else:
            return 1
    except:
        return 0


def add_result2(type):
    try:
        if type.lower() == "good":
            return 0
        else:
            return 1
    except:
        return 0


def fd_length(url):
    urlpath = urlparse(url).path
    try:
        str = urlpath.split('/')[1]
        return len(str)
    except:
        return 0


def tld_length(domain):
    try:

        copy = domain
        if not (domain.count('http') or domain.count('https')):
            copy = "http://" + copy
        tld = get_tld(copy)
        return len(tld)
    except:
        return 0


def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


def no_of_dir(url):
    url_dir = urlparse(url).path
    return url_dir.count('/')


def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0


def hostname_len(url):
    try:
        if not (url.count('http') or url.count('https')):
            url = "http://" + url
        h_len = len(urlparse(url).netloc)
        return h_len
    except:
        return 0


def tld_len(url):
    try:
        if not (url.count('http') or url.count('https')):
            url = "http://" + url
        t_len = len(get_tld(url))
        return t_len
    except:
        return 0


def path_len(url):
    try:
        if not (url.count('http') or url.count('https')):
            url = "http://" + url
        p_len = len(urlparse(url).path)
        return p_len
    except:
        return 0


def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 0
    else:
        return 1


def has_client_in_string(url):
    if 'client' in url.lower():
        return 1
    return 0


def has_admin_in_string(url):
    if 'admin' in url.lower():
        return 1
    return 0


def has_server_in_string(url):
    if 'server' in url.lower():
        return 1
    return 0


def has_login_in_string(url):
    if 'login' in url.lower():
        return 1
    return 0


def number_of_fragments(url):
    frags = urlparse(url).fragment
    return len(frags.split('#')) - 1 if frags == '' else 0


def number_of_parameters(url):
    params = urlparse(url).query
    return 0 if params == '' else len(params.split('&'))


def get_entropy(url):
    url = url.lower()
    probs = [url.count(c) / len(url) for c in set(url)]
    entropy = -sum([p * log(p) / log(2.0) for p in probs])
    return entropy


def number_of_periods(url):
    periods = [i for i in url if i == '.']
    return len(periods)


def get_IP(url):
    try:
        d_name = url.split('/')
        if url.count('http') or url.count('https'):
            return d_name[2]
        else:
            return d_name[0]

    except:
        return "--"


def get_IPWhois_Info(df):
    create_date = "-"
    registry = "-"
    country = "-"
    cidr = "-"
    update_date = "-"
    i = 0
    buffer = None
    for url in df["url"]:
        try:
            hostname = get_IP(url)
            if i == 0:
                buffer = hostname
            if buffer != hostname or i == 0:
                IP = socket.gethostbyname(hostname)
                obj = IPWhois(IP)
                res = obj.lookup_whois()
                create_date = res.get("asn_date")
                registry = res.get("asn_registry")
                cidr = res.get("asn_cidr")
                country = res.get("asn_country_code")
                update_date = res.get("nets")[0].get("updated")
                buffer = hostname
            # return create_date, registry, cidr, country, update_date
        except:
            create_date = "-"
            registry = "-"
            country = "-"
            cidr = "-"
            update_date = "-"
        df.at[i, 'create_date'] = create_date
        df.at[i, 'registry'] = registry
        df.at[i, 'country'] = country
        df.at[i, 'cidr'] = cidr
        df.at[i, 'update_date'] = update_date
        i += 1
    # return create_date, registry, country, update_date


class features:
    def __init__(self, source, dest):
        self.source = source
        self.dest = dest

    def extract_features(self):
        df = pd.read_csv(self.source)
        df_features = df.dropna()

        df_features['url_length'] = df['url'].apply(lambda i: len(i))
        df_features['hostname_length'] = df['url'].apply(lambda i: hostname_len(i))
        df_features['path_length'] = df['url'].apply(lambda i: path_len(i))
        df_features['fd_length'] = df['url'].apply(lambda i: fd_length(i))
        df_features['tld_length'] = df_features['url'].apply(lambda i: tld_length(i))

        df_features['n-'] = df['url'].apply(lambda i: i.count('-'))
        df_features['n_'] = df['url'].apply(lambda i: i.count('_'))
        df_features['n@'] = df['url'].apply(lambda i: i.count('@'))
        df_features['n?'] = df['url'].apply(lambda i: i.count('?'))
        df_features['n%'] = df['url'].apply(lambda i: i.count('%'))
        df_features['n.'] = df['url'].apply(lambda i: i.count('.'))
        df_features['n='] = df['url'].apply(lambda i: i.count('='))
        df_features['n-http'] = df['url'].apply(lambda i: i.count('http'))
        df_features['n-https'] = df['url'].apply(lambda i: i.count('https'))
        df_features['n-www'] = df['url'].apply(lambda i: i.count('www'))
        df_features['n-digits'] = df['url'].apply(lambda i: digit_count(i))
        df_features['n-letters'] = df['url'].apply(lambda i: letter_count(i))
        df_features['n-dir'] = df['url'].apply(lambda i: no_of_dir(i))
        df_features['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))
        df_features['short_url'] = df['url'].apply(lambda i: shortening_service(i))
        df_features['n_param'] = df['url'].apply(lambda i: number_of_parameters(i))
        df_features['entropy'] = df['url'].apply(lambda i: get_entropy(i))
        df_features['login'] = df['url'].apply(lambda i: has_login_in_string(i))
        df_features['server'] = df['url'].apply(lambda i: has_server_in_string(i))
        df_features['admin'] = df['url'].apply(lambda i: has_admin_in_string(i))
        df_features['client'] = df['url'].apply(lambda i: has_client_in_string(i))
        df_features.to_csv(self.dest, index=False)

        y = df_features['result']
        return df_features, y
