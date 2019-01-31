--限制接口时间窗请求数
--限制 ip 每分钟只能调用 120 次 /hello 接口（允许在时间段开始的时候一次性放过120个请求）

local limit_count = require "resty.limit.count"

-- rate: 10/min 
local lim, err = limit_count.new("my_limit_count_store", 120, 60)
if not lim then
    ngx.log(ngx.ERR, "failed to instantiate a resty.limit.count object: ", err)
    return ngx.exit(500)
end

local key = ngx.var.binary_remote_addr
local delay, err = lim:incoming(key, true)
-- 如果请求数在限制范围内，则当前请求被处理的延迟（这种场景下始终为0，因为要么被处理要么被拒绝）和将被处理的请求的剩余数
if not delay then
    if err == "rejected" then
        return ngx.exit(503)
    end

    ngx.log(ngx.ERR, "failed to limit count: ", err)
    return ngx.exit(500)
end
