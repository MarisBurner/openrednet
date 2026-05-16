local match, sub = string.match, string.sub

local function parseUrl(url)
    local pos = 1
    -- URL format: scheme://subdomain.domain.tld[:port](/path)*(%?(key=value)+)?(#fragment)?

    -- Parse scheme
    local scheme = match(url, "^(%w+)://", pos)
    if not scheme then return nil, "could not parse scheme" end
    pos = pos + #scheme + 3 -- Skip "://"

    -- Parse host
    local subdomain, domain, tld, port = match(url, "([^%.]+)%.([^%.]+)%.(%w+)", pos)
    if not subdomain then return nil, "could not parse host" end
    pos = pos + #subdomain + #domain + #tld + 1

    -- Parse path
    local path = {}
    while true do
        local pathPart = match(url, "/%w+", pos)
        if not pathPart then break end
        path[#path + 1] = pathPart
        pos = pos + #pathPart
    end

    -- Parse query
    local query = {}
    if match(url, "%?") then
        while true do
            local key, value = match(url, "%?(%w+)=(%w+)", pos)
            if not key then break end
            query[key] = value
            pos = pos + #key + 1 + #value
            if sub(url, pos, pos) ~= "&" then break end
            pos = pos + 1
        end
    end
    if query then pos = pos + #query end

    -- Parse fragment
    local fragment = match(url, "(#%w+)", pos)
    if fragment then pos = pos + #fragment end

    return {
        scheme = scheme,
        subdomain = subdomain,
        domain = domain,
        tld = tld,
        path = path,
        query = query,
        fragment = fragment,
    }
end

return parseUrl
