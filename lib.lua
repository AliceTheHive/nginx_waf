--Get the client ip
function getClientIp()
        headers=ngx.req.get_headers()
        --IP  = ngx.var.remote_addr 
        IP = headers["X-REAL-IP"] or headers["X_FORWARDED_FOR"] or ngx.var.remote_addr or nil
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end

--Get the client user agent
function get_user_agent()
    USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
       USER_AGENT = "unknown"
    end
    return USER_AGENT
end

--Get the rule from file
function read_rule(var)
    file = io.open(config_rule_dir..'/'..var, "r")
    if file == nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

--WAF return
function waf_output()
    if config_waf_output == "redirect" then
        ngx.redirect(config_waf_redirect_url, 301)
    elseif config_waf_output == "html" then
        local nowhtml = config_output_html
        ngx.header.content_type = "text/html;charset=UTF-8"
        ngx.status = ngx.HTTP_FORBIDDEN
        nowhtml = string.gsub(nowhtml, "{ip}", getClientIp())
        nowhtml = string.gsub(nowhtml, "{time}", ngx.localtime())
        nowhtml = string.gsub(nowhtml, "{code}", ngx.status)
        nowhtml = string.gsub(nowhtml, "{host}", ngx.var.host)
        ngx.say(nowhtml)
        ngx.exit(403)
    elseif config_waf_output == "json" then
        local json = require "json"
        ngx.header.content_type = "application/json;charset=utf-8"
        ngx.status = ngx.HTTP_FORBIDDEN
        local ret = {
            clientip = getClientIp(),
            timestamp = ngx.localtime(),
            status = ngx.status,
            http_host = ngx.var.host,
            }
        ngx.say(json.encode(ret))
        ngx.exit(403)
    end
end

--WAF log record for json,(use logstash codec => json)
function log_record(method,url,data,ruletag)
    if config_log_enable = "on" then
        local json = require("json")
        local io = require 'io'
        local CLIENT_IP = getClientIp()
        local USER_AGENT = get_user_agent()
        local SERVER_NAME = ngx.var.host
        local LOCAL_TIME = ngx.localtime()
        local log_json_obj = {
                 client_ip = CLIENT_IP,
                 local_time = LOCAL_TIME,
                 server_name = SERVER_NAME,
                 user_agent = USER_AGENT,
                 attack_method = method,
                 req_url = url,
                 req_data = data,
                 rule_tag = ruletag,
              }
        local LOG_LINE = json.encode(log_json_obj)
        local file = io.open(config_log_dir..'/'..ngx.today().."_waf.log", "a")
        if file == nil then
            return
        end
        file:write(LOG_LINE.."\n")
        file:flush()
        file:close()
    end
end

--debug info
function debug_log(info)
    local io = require 'io'
    local file, err = io.open(config_log_dir.."/debug.log", "a")
    if file == nil then
        print("Couldn't open file: "..err)
    else
        file:write(info.."\n")
        file:flush()
        file:close()
    end
end
