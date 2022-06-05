import nmap
import requests
import re

# regex to get version id
def get_version_id(host,port):
	req = requests.head("http://{}".format(host))
	filter_req = re.search(r"/.* ",req.headers['Server']).group()
	return filter_req[1::]
	
def regex_version_id(ver_apa):
	
    for n in range(1,12):
        req_get_response = requests.get("https://www.cvedetails.com/version-list/45/66/{}/Apache-Http-Server.html?order=1".format(n))
        list_dot = ["....",".....","......"]
        for a in list_dot:
            get_ver_id = re.findall(r"/vulnerability-list/vendor_id-45/product_id-66/version_id-{}/Apache-Http-Server-{}.html".format(a,ver_apa), str(req_get_response.content))
            if len(get_ver_id) >= 1 :
                for i in get_ver_id:
                    filtered = re.search(r"\bversion_id.*/",i).group(0)
                    result = request_get_api(filtered)
			

# instantiate a PortScanner object

def nmap_scan(host,port,ver_id):
	sc = nmap.PortScanner()
   
	
	result = sc.scan(host,port,arguments=" --script /home/nam/docker/custom-script.nse --script-args 'ver_id={}' ".format(ver_id))
	return result
	
host = str(input("input host : "))
port = str(input("input port : "))
print(get_version_id(host,port))
print(nmap_scan(host,port, get_version_id(host,port)))
