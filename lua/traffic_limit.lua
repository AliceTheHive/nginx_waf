-- http 配置
-- lua_package_path "/opt/programs/nginx_1.14.2/conf/waf/lua/?.lua;;";
-- lua_shared_dict limit_req_store 100m;
-- location 配置
-- access_by_lua_file /path/to/your/resty-limit.lua;

local limit_req = require "resty.limit.req"
local rate = 2 --固定平均速率2r/s
local burst = 10 --桶容量
local error_status = 503
local nodelay = true --是否需要不延迟处理
local lim, err = limit_req.new("limit_req_store", rate, burst)
if not lim then --没定义共享字典
    ngx.exit(error_status)
end
local key = ngx.var.binary_remote_addr --IP维度限流
--请求流入，如果你的请求需要被延迟则返回delay>0
local delay, err = lim:incoming(key, true)
if not delay and err == "rejected" then
    ngx.exit(error_status)
end
if delay > 0 then --根据需要决定延迟或者不延迟处理
    if nodelay then
        --直接突发处理
    else
        ngx.sleep(delay) --延迟处理
    end
end
