-- HEAD SECTON

local http = require "http"

-- RULE SECTION
portrule = function(host,port)
	return port.protocol == 'tcp' or 'udp' and port.number == 80 or 443
end 

-- hostrule

-- prerule 

-- postrule

-- action section
action = function(host, port)
    	
	-- The Vuln Definition Section --
	local vuln = {
    		title = " Apache HTTP Server 2.4.50 Vulneribility" ,
    		IDS = { CVE = 'CVE-2021-42013' }
}

	local uri = "/index.html"
	local reponse = http.head(host,port,uri)
	if ( reponse.status == 200 ) then 
		if ( reponse.header.server:match "Apache/2.4.50") then
			return vuln
		else
			return " Maybe Safety ! "	
		end
	
	else
		return " Something Wrong ! "
	end
	
end	

