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

action = function(host, port , ver_id)
	local option={
    		header={
      			['User-Agent'] = string.format('Vulners NMAP Plugin %s', api_version),
		        ['Accept-Encoding'] = "gzip, deflate"
    		},
	        any_af = true,
  	}
  	
  	-- get apache version
	local uri = "/index.html"
	local response = http.head(host,port,uri)
	local apache_ver = response.header.server
	

	local api_host = "https://www.cvedetails.com/json-feed.php"
	local result  = http.get_url(("%s?version_id=%s"):format(api_host,ver_id),option)
	return ver_id
end	

