import nmap
import requests
import re

def get_version_apa(host,port):
	# send head request to host ip
		req = requests.head("http://{}".format(host))
		#filter result to get version of apache server 
		filter_req = re.search(r"/.* ",req.headers['Server']).group()
		return filter_req[1:-1:]
	
def regex_version_id(ver_apa):
	#send request to cvedetails.com to get version_id of apache on website
	 
	for n in range(1,12):
	#send request from page 1 to page 2 to get reponse
		
		req_get_response = requests.get("https://www.cvedetails.com/version-list/45/66/{}/Apache-Http-Server.html?order=1".format(n))
		# list_dot will help in regex process to filter version_id 
		# because one apache version can have multiple version_id like 32222, 2333, 232442
		lst_dot = ["....",".....","......"]
		for dot in lst_dot:
			# regex the reponse to get output 
			# output will look like:  [/vulnerability-list/vendor_id-45/product_id-66/version_id-323322/Apache-Http-Server-2.4.50.html]
			get_ver_id = re.findall(r'href="/vulnerability-list/vendor_id-45/product_id-66/version_id-{}/Apache-Http-Server-{}.html"'.format(dot,str(ver_apa)),str(req_get_response.content))
			
			# result >= 1 
			if len(get_ver_id) >= 1 :
				for i in get_ver_id:
					# filter the output and the version_id will look like 622345
					filtered = re.search(r"\bversion_id.*/",i).group()				
					return filtered[12::]

		print(" NOT FOUND CVE FOR THIS VERSION " )	

def nmap_scan_port():
	host = str(input("input host : "))

	print("input a range of port to scan")
	begin_port = int(input("Begining port : "))

	end_port = int(input("Ending port: "))
	min_port = 1
	max_port = 65535
	if (begin_port >= min_port and end_port <= max_port):
		for i in range(begin_port, end_port + 1 ):
			sc = nmap.PortScanner()
			result = sc.scan(host,'{}'.format(i))	
			print(result)
	else:
		print("Invalid Port")


def nmap_scan_vul():
	host = str(input("input host : "))
	port = str(input("input port "))

	ver_apa = get_version_apa(host,port)
	ver_id = regex_version_id(ver_apa)
	sc = nmap.PortScanner()
	if ver_id != None:
	# use nmap-python to scan vulnerability with nmap script and pass the version_id to nmap script
		result = sc.scan(host,port,arguments=" --script /home/nam/python_nma_nse/nmap-script.nse -d --script-args ver_id={} ".format(ver_id))
		print(result)
	else:
		return "Not found CVE for apache version {}".format(ver_apa)



#print(nmap_scan_vul(host,port,get_version_apa(host,port)))
#nmap_scan(host,port,get_version_apa(host,port ))
if __name__ == "__main__":
	print("-----------------------NMAP SCANNING TOOL---------------------------")
	print("1. Scan open port of port ")
	print("2. Scan CVE of version Apache version")
	print("3. Exit ")
	answer = int(input("please input an answer "))
	match answer:
		case 1: 
			nmap_scan_port(),
		case 2: 
			nmap_scan_vul(),
		case 3:
			pass
