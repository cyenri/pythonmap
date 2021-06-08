#!/usr/bin/python3

import nmap

print('  ___                 _   _   _      _ ') 
print(' / _ \               | | | \ | |    | |  ')
print('/ /_\ \_   ____ _ ___| |_|  \| | ___| |_ ')
print('|  _  \ \ / / _` / __| __| . ` |/ _ \ __|')
print('| | | |\ V / (_| \__ \ |_| |\  |  __/ |_ ')
print('\_| |_/ \_/ \__,_|___/\__\_| \_/\___|\__|')

print("[Info] Herramienta para escanear los puertos abiertos en una dirección IP")

ip=input("[+] Ingrese la ip que desea escanear ==> ")
nm = nmap.PortScanner()
puertos_abiertos="-p "
results = nm.scan(hosts=ip,arguments="-sT -n -Pn -T4")
count=0
#print (results)
print("\nHost : %s" % ip)
print("State : %s" % nm[ip].state())
for proto in nm[ip].all_protocols():
	print("Protocol : %s" % proto)
	print()
	lport = nm[ip][proto].keys()
	sorted(lport)
	for port in lport:
		print ("port : %s\tstate : %s" % (port, nm[ip][proto][port]["state"]))
		if count==0:
			puertos_abiertos=puertos_abiertos+str(port)
			count=1
		else:
			puertos_abiertos=puertos_abiertos+","+str(port)

print("\nPuertos abiertos: "+ puertos_abiertos +" "+str(ip))