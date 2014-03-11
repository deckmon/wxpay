#-*- coding:utf-8 -*-

from django.conf import settings as dj_settings


class settings(object):

    WXPAY_APPID = "YOUR_APPID"
    WXPAY_PAYSIGNKEY = "YOUR_PAYSIGNKEY"
    WXPAY_APPSECRET = "YOUR_APPSECRET"
    WXPAY_PARTNERID = "YOUR_PARTNERID"
    WXPAY_PARTNERKEY = "YOUR_PARTNERKEY"
    
    INPUT_CHARSET = "GBK"
    
    @classmethod
    def get_notify_url(cls):
        # 交易过程中服务器异步通知的页面 要用 http://格式的完整路径
        return "YOUR_ABSOLUTE_NOTIFY_URL"