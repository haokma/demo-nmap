import nmap
import requests
import re

# regex to get version id
def get_version_apa(host,port):
	req = requests.head("http://{}".format(host))
	filter_req = re.search(r"/.* ",req.headers['Server']).group()
	return filter_req[1::]
	
def regex_version_id(ver_apa):
    print(ver_apa)
    for n in range(1,12):
        req_get_response = requests.get("https://www.cvedetails.com/version-list/45/66/{}/Apache-Http-Server.html?order=1".format(n))
        
        get_ver_id = re.findall(r"/vulnerability-list/vendor_id-45/product_id-66/version_id-.*/Apache-Http-Server-{}.html".format(ver_apa), str(req_get_response.content))
        print(get_ver_id)
        if len(get_ver_id) >= 1 :
            for i in get_ver_id:
                filtered = re.search(r"\bversion_id.*/",i).group()
		        
		        return filtered
		else:
			continue



def nmap_scan(host,port,ver_apa):
	sc = nmap.PortScanner()
   
	ver_id = regex_version_id(ver_apa)
	result = sc.scan(host,port,arguments=" --script /home/nam/docker/custom-script.nse --script-args 'ver_id={}' ".format(ver_id))
	return result
	
host = str(input("input host : "))
port = str(input("input port : "))
print(nmap_scan(host,port,get_version_apa(host,port )))
