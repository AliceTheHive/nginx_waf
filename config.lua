--WAF config file,enable = "on",disable = "off"

config_waf_enable = "on"
config_log_dir = "/opt/programs/nginx_1.14.2/logs/hack"
config_rule_dir = "/opt/programs/nginx_1.14.2/conf/waf/rules"
config_ip_white_check = "on"
config_ip_black_check = "on"
config_white_url_check = "on"
config_url_check = "on"
config_args_check = "on"
config_agent_check = "on"
config_cookie_check = "on"
config_cc_check = "on"
config_cc_rate = "10/60"
config_post_check = "off" -- close
config_waf_output = "json" -- html/json/redirect
config_waf_redirect_url = "https://ip.cn" -- redirect url
config_output_html=[[
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>HTTP Error {code}</title>
</head>
<body bgcolor="white">
<center><h1>HTTP ERROR {code}</h1></center>
<hr>
<p>host: {host}</p>
<p>clientip: {ip}</p>
<p>timestamp: {time}</p>
</body>
</html>
]]
