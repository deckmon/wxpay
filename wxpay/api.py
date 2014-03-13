# -*- coding: utf-8 -*-

'''
Created on 2014-3-10
微信支付接口
@author: Deckmon
'''

import json
import types
from random import Random
from time import time as ttime
from collections import defaultdict
from xml.etree import cElementTree as ET
from urllib import urlopen

from hashcompat import md5_constructor as md5, sha_constructor as sha1
from config import settings

DELIVER_NOTIFY_URL = "https://api.weixin.qq.com/pay/delivernotify"


def etree_to_dict(t):
    d = {t.tag: {} if t.attrib else None}
    children = list(t)
    if children:
        dd = defaultdict(list)
        for dc in map(etree_to_dict, children):
            for k, v in dc.iteritems():
                dd[k].append(v)
        d = {t.tag: {k:v[0] if len(v) == 1 else v for k, v in dd.iteritems()}}
    if t.attrib:
        d[t.tag].update(('@' + k, v) for k, v in t.attrib.iteritems())
    if t.text:
        text = t.text.strip()
        if children or t.attrib:
            if text:
              d[t.tag]['#text'] = text
        else:
            d[t.tag] = text
    return d


def xml_to_dict(xml_text):
    e = ET.XML(smart_str(xml_text))
    return etree_to_dict(e)


always_safe = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
               'abcdefghijklmnopqrstuvwxyz'
               '0123456789' '_.-')
_safemaps = {}

def my_quote(s, safe = '/'):
    """quote('abc def') -> 'abc%20def'

    Each part of a URL, e.g. the path info, the query, etc., has a
    different set of reserved characters that must be quoted.

    RFC 2396 Uniform Resource Identifiers (URI): Generic Syntax lists
    the following reserved characters.

    reserved    = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" |
                  "$" | ","

    Each of these characters is reserved in some component of a URL,
    but not necessarily in all of them.

    By default, the quote function is intended for quoting the path
    section of a URL.  Thus, it will not encode '/'.  This character
    is reserved, but in typical usage the quote function is being
    called on a path where the existing slash characters are used as
    reserved characters.
    """
    cachekey = (safe, always_safe)
    try:
        safe_map = _safemaps[cachekey]
    except KeyError:
        safe += always_safe
        safe_map = {}
        for i in range(256):
            c = chr(i)
            safe_map[c] = (c in safe) and c or ('%%%02x' % i)
        _safemaps[cachekey] = safe_map
    res = map(safe_map.__getitem__, s)
    return ''.join(res)


def my_quote_plus(s, safe = ''):
    """Quote the query fragment of a URL; replacing ' ' with '+'"""
    if ' ' in s:
        s = my_quote(s, safe + ' ')
        return s.replace(' ', '+')
    return my_quote(s, safe)


def random_str(randomlength=8):
    str = ''
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    length = len(chars) - 1
    random = Random()
    for i in range(randomlength):
        str+=chars[random.randint(0, length)]
    return str


def smart_str(s, encoding='utf-8', strings_only=False, errors='strict'):
    """
    Returns a bytestring version of 's', encoded as specified in 'encoding'.

    If strings_only is True, don't convert (some) non-string-like objects.
    """
    if strings_only and isinstance(s, (types.NoneType, int)):
        return s
    if not isinstance(s, basestring):
        try:
            return str(s)
        except UnicodeEncodeError:
            if isinstance(s, Exception):
                # An Exception subclass containing non-ASCII data that doesn't
                # know how to print itself properly. We shouldn't raise a
                # further exception.
                return ' '.join([smart_str(arg, encoding, strings_only,
                        errors) for arg in s])
            return unicode(s).encode(encoding, errors)
    elif isinstance(s, unicode):
        return s.encode(encoding, errors)
    elif s and encoding != 'utf-8':
        return s.decode('utf-8', errors).encode(encoding, errors)
    else:
        return s


def params_filter(params, except_keys=[]):
    # 对数组排序并除去数组中的空值和签名参数
    # 返回数组和链接串
    ks = params.keys()
    ks.sort()
    newparams = {}
    prestr = ''
    for k in ks:
        v = params[k]
        k = smart_str(k, settings.INPUT_CHARSET)
        if k not in except_keys and v != '':
            newparams[k] = smart_str(v, settings.INPUT_CHARSET)
            prestr += '%s=%s&' % (k, newparams[k])
    prestr = prestr[:-1]
    return newparams, prestr


def params_urlencode(params):
    newparams = {}
    for key in params:
        newparams[key] = my_quote_plus(params[key]).replace("+", "%20")
    return newparams


def params_to_string(params):
    keys = params.keys()
    keys.sort()
    res = ""
    for key in keys:
        res += '%s=%s&' % (key, params[key])
    return res[:-1]


def build_mysign(prestr, key, sign_type='MD5'):
    if sign_type == 'MD5':
        return md5(prestr + "&key=" + key).hexdigest().upper()
    return ""


def get_brand_wc_pay_request(body, out_trade_no, total_fee, ip, attach=""):
    # total_fee 为字符串，单位是分
    params = {}
    params["appId"] = settings.WXPAY_APPID
    params["timeStamp"] = "%.f" % ttime()
    params["nonceStr"] = random_str(13)
    
    package = {}
    package["bank_type"] = "WX"
    package["body"] = body                            # 商品描述;
    package["attach"] = attach                        # 附加数据,原样返回;
    package["partner"] = settings.WXPAY_PARTNERID
    package["out_trade_no"] = out_trade_no            # 商户系统内部的订单号,32 个字符内、可包含字 母,确保在商户系统唯一;
    package["total_fee"] = total_fee                  # 订单总金额,单位为分;
    package["fee_type"] = 1
    package["notify_url"] = settings.get_notify_url()
    package["spbill_create_ip"] = ip
    package["time_start"] = ""
    package["time_expire"] = ""
    package["transport_fee"] = ""
    package["product_fee"] = ""
    package["goods_tag"] = ""
    package["input_charset"] = settings.INPUT_CHARSET
    
    package,packageprestr = params_filter(package)
    
    sign_value = build_mysign(packageprestr, settings.WXPAY_PARTNERKEY, sign_type = "MD5")
    package = params_urlencode(package)
    package = params_to_string(package) + "&sign=" + sign_value
    
    params["package"] = package
    
    params["appkey"] = settings.WXPAY_PAYSIGNKEY
    lower_params = {}
    for key in params:
        lower_params[key.lower()] = params[key]
    lower_params,lower_paramsprestr = params_filter(lower_params)
    pay_sign = sha1(lower_paramsprestr).hexdigest()
    
    del params["appkey"]
    params["signType"] = "SHA1"
    params["paySign"] = pay_sign
    return params


def parse_notify_body(body):
    return xml_to_dict(body)["xml"]


def verify_get(get):
    _,prestr = params_filter(get, except_keys=["sign"])    
    mysign = build_mysign(prestr, settings.WXPAY_PARTNERKEY, sign_type = "MD5").upper()
    if mysign != get.get('sign'):
        return False
    return True


def verify_post(post_data):
    if not isinstance(post_data, dict):
        post_data = parse_notify_body(post_data)

    lower_params = {}
    for key in post_data:
        lower_params[key.lower()] = post_data[key]
    lower_params["appkey"] = settings.WXPAY_PAYSIGNKEY
    lower_params.pop("signmethod", None)
    app_signature = lower_params.pop("appsignature")
    lower_params,lower_paramsprestr = params_filter(lower_params)
    my_app_signature = sha1(lower_paramsprestr).hexdigest()

    if my_app_signature != app_signature:
        return False
    return True


def notify_verify(get, post_data):
    return verify_get(get) and verify_post(post_data)


def deliver_notify(access_token, openid, transid, out_trade_no):
    url = DELIVER_NOTIFY_URL + "?access_token=" + access_token
    payload = {
        "appid": settings.WXPAY_APPID,
        "openid": openid,
        "transid": transid,
        "out_trade_no": out_trade_no,
        "deliver_timestamp": "%.f" % ttime(),
        "deliver_status": "1",
        "deliver_msg": "ok",

    }
    payload["appkey"] = settings.WXPAY_PAYSIGNKEY
    payload,payloadprestr = params_filter(payload)
    app_signature = sha1(payloadprestr).hexdigest()
    del payload["appkey"]
    payload["app_signature"] = app_signature
    payload["sign_method"] = "sha1"
    payload = json.dumps(payload)
    res = json.loads(urlopen(url, payload).read())
    return res