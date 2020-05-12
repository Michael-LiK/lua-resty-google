--
-- root@20200512
--
local hmac = require 'resty.evp'

local _M = {}

local function safe_trans(str)
    str = str:gsub("[+/]", function(c)
        if c == '+' then
            return '-'
        else
            return '_'
        end
    end)
    return str
end

function _M.get_jwt(private_key, iss, exp)
    local iat = ngx.time() 
    local header = '{"alg":"RS256","typ":"JWT"}'
    local payload = '{"iss":"'.. iss ..'","scope":"https://www.googleapis.com/auth/prediction","aud":"https://oauth2.googleapis.com/token","exp":'.. exp ..',"iat":'.. iat ..'}'

    local header_url = safe_trans(ngx.encode_base64(header))
    local pay_load_url = safe_trans(ngx.encode_base64(payload))

    local str = header_url .. '.' .. pay_load_url

    local signer, err = evp.RSASigner:new(key)
    if not signer then
      error({reason="signer error: " .. err})
    end

    local signature = signer:sign(str, evp.CONST.SHA256_DIGEST)
    signature = safe_trans(ngx.encode_base64(signature))

    return str .. '.' signature
end

return _M

