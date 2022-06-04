import nmap
   
# instantiate a PortScanner object
sc = nmap.PortScanner()
   
    # scan the target port

result = sc.scan('127.0.0.1','80',arguments='--script custom-script ')
print(result)
