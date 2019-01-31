--漏桶算法限流
--限制 ip 每分钟只能调用 120 次 /hello 接口（平滑处理请求，即每秒放过2个请求），超过部分进入桶中等待，（桶容量为60），如果桶也满了，则进行限流

local limit_req = require "resty.limit.req"
-- 这里设置rate=2/s，漏桶桶容量设置为0，（也就是来多少水就留多少水） 
-- 因为resty.limit.req代码中控制粒度为毫秒级别，所以可以做到毫秒级别的平滑处理
local lim, err = limit_req.new("my_limit_req_store", 2, 60)
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
-- 所以此处对桶中请求进行延时处理，让其排队等待，就是应用了漏桶算法
-- 此处也是与令牌桶的主要区别既
if delay >= 0.001 then
    ngx.sleep(delay)
end
