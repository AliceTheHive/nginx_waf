--令牌桶算法限流
--限制 ip 每分钟只能调用 120 次 /hello 接口（平滑处理请求，即每秒放过2个请求），但是允许一定的突发流量（突发的流量，就是桶的容量（桶容量为60），超过桶容量直接拒绝

local limit_req = require "resty.limit.req"

local lim, err = limit_req.new("my_limit_req_store", 2, 0)
if not lim then
    ngx.log(ngx.ERR, "failed to instantiate a resty.limit.req object: ", err)
    return ngx.exit(500)
end

local key = ngx.var.binary_remote_addr
local delay, err = lim:incoming(key, true)
if not delay then
    if err == "rejected" then
        return ngx.exit(503)
    end
    ngx.log(ngx.ERR, "failed to limit req: ", err)
    return ngx.exit(500)
end

-- 此方法返回，当前请求需要delay秒后才会被处理，和他前面对请求数
-- 此处忽略桶中请求所需要的延时处理，让其直接返送到后端服务器，
-- 其实这就是允许桶中请求作为突发流量 也就是令牌桶桶的原理所在
if delay >= 0.001 then
--    ngx.sleep(delay)
end
