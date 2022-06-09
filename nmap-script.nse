-- HEAD SECTON

local http = require "http"
local api_version="1.7"


-- RULE SECTION
portrule = function(host,port)
	return port.protocol == 'tcp' or 'udp' and port.number == 80 or 443
end 

-- hostrule

-- prerule 

-- postrule

-- action section

--function req_api(port)
	
--end

action = function(host, port )
	local option={
    		header={
      			['User-Agent'] = string.format('Vulners NMAP Plugin %s', api_version),
		        ['Accept-Encoding'] = "gzip, deflate"
    		},
	        any_af = true,
  	}
  	
	
	

	local api_host = "https://www.cvedetails.com/json-feed.php"
	--local result  = http.get_url(("%s?version_id=%s"):format(api_host,nmap.registry.args.ver_id),option)
	uri = ("/json-feed.php?version_id=%s"):format(nmap.registry.args.ver_id)
	local result = http.get("https://www.cvedetails.com",port,uri)
	return result
end	

