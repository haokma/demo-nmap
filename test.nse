local shortport = require "shortport"
local http = require "http"

-- The Rule Section --
portrule = shortport.http

-- The Action Section --
action = function(host, port)

    local uri = "/index.html"
    local response = http.get(host, port, uri)
    return response.status

end
