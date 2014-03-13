WX Pay
=========

微信支付

## 主要提供函数：

- get_brand_wc_pay_request：获取传递给getBrandWCPayRequest的参数
- deliver_notify：确认发货
- notify_verify：验证微信请求
- verify_get：单独验证GET参数
- verify_post：单独验证POST传递的xml
- parse_notify_body：将微信通过POST传递来的xml转换为dict
