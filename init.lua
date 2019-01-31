--WAF Action
require 'config'
require 'lib'

--args
local ngxmatch=ngx.re.match
local unescape = ngx.unescape_uri

--readrules
ipWhiteRules=read_rule('ipwhite.rule')
ipBlockRules=read_rule('ipblock.rule')
urlWhiteRules=read_rule('urlwhite.rule')
urlBlockRules=read_rule('urlblock.rule')
argsRules=read_rule('args.rule')
agentRules=read_rule('useragent.rule')
postRules=read_rule('post.rule')
cookieRules=read_rule('cookie.rule')

--allow white ip
function ip_white_check()
    if config_ip_white_check == "on" then
        if next(ipWhiteRules) ~= nil then 
            local client_ip = getClientIp()
            for _,ip in pairs(ipWhiteRules) do
                if client_ip == ip then
                    return true
                end
            end
        end
    end
    return false
end

--deny black ip
function ip_black_check()
    if config_ip_black_check == "on" then
        if next(ipBlockRules) ~= nil then 
            local client_ip = getClientIp()
            for _,ip in pairs(ipBlockRules) do
                if client_ip == ip then
                    ngx.exit(403)
                    return true
                end
            end
        end
    end
    return false
end

--allow white url
function url_white_check()
    if config_url_white_check == "on" then
        if urlWhiteRules ~= nil then
            for _,rule in pairs(urlWhiteRules) do
                if ngxmatch(ngx.var.uri,rule,"isjo") then
                    return true
                end
            end
        end
    end
    return false
end

--deny black url
function url_black_check()
    if config_url_black_check == "on" then
        if urlBlockRules ~= nil then
            for _,rule in pairs(urlBlockRules) do
                if rule ~= "" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
                    log_record('BLACK_URL',ngx.var.request_uri,"-",rule)
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny cc attack
function cc_attack_check()
    if config_cc_check == "on" then
        local URI = ngx.var.uri
        local TOKEN = getClientIp()..URI
        local limit = ngx.shared.limit
        CCcount=tonumber(string.match(config_cc_rate,'(.*)/'))
        CCseconds=tonumber(string.match(config_cc_rate,'/(.*)'))
        local req,_ = limit:get(TOKEN)
        if req then
            if req > CCcount then
                log_record('CC_Attack',ngx.var.request_uri,"-","-")
                waf_output()
                return true
            else
                limit:incr(TOKEN,1)
            end
        else
            limit:set(TOKEN,1,CCseconds)
        end
    end
    return false
end

--deny cookie
function cookie_attack_check()
    local COOKIE = ngx.var.http_cookie
    if config_cookie_check == "on" and COOKIE then
        for _,rule in pairs(cookieRules) do
            if rule ~="" and ngxmatch(COOKIE,rule,"isjo") then
                log_record('Deny_Cookie',ngx.var.request_uri,"-",rule)
                waf_output()
                return true
            end
        end
    end
    return false
end

--deny url
function url_attack_check()
    if config_url_check == "on" then
        if urlBlockRules ~= nil then
            for _,rule in pairs(urlBlockRules) do
                if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
                    log_record('Deny_URL',ngx.var.request_uri,"-",rule)
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny args
function args_attack_check()
    if config_args_check == "on" then
        for _,rule in pairs(argsRules) do
            local ARGS = ngx.req.get_uri_args()
            for key, val in pairs(ARGS) do
                if type(val) == 'table' then
                    local t = {}
                    for k,v in pairs(val) do
                        if v == true then
                            v = ""
                        end
                        table.insert(t,v)
                    end
                    ARGS_DATA = table.concat(t, " ")
                else
                    ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and ngxmatch(unescape(ARGS_DATA),rule,"isjo") then
                    log_record('Deny_Args',ngx.var.request_uri,"-",rule)
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny agent
function agent_attack_check()
    if config_agent_check == "on" then
        local AGENT = ngx.var.http_user_agent
        if AGENT ~= nil then
            for _,rule in pairs(agentRules) do
                if rule ~="" and ngxmatch(AGENT,rule,"isjo") then
                    log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule)
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny post
function post_attack_check()
    if config_post_check == "on" then
        for _,rule in pairs(postRules) do
            if rule ~="" and data~="" and ngxmatch(unescape(data),rule,"isjo") then
                log_record('Deny_POST',ngx.var.request_uri,data,rule)
                waf_output()
                return true
            end
        end
    end
    return false
end
