#!/usr/bin/env python3
__version__ = "1.0"
import json
import os
import sys
sys.path.append("/Users/jozbox/python/functions")
import file
parent_dir = os.path.dirname(__file__)
servers_json = json.load(open(parent_dir + "/nordvpn.com_servers.json"))
servers_standard = []
servers_standard_path = parent_dir + "/servers_standard.txt"
servers_dedicated = []
servers_dedicated_path = parent_dir + "/servers_dedicated.txt"
servers_obfuscated = []
servers_obfuscated_path = parent_dir + "/servers_obfuscated.txt"
servers_p2p = []
servers_p2p_path = parent_dir + "/servers_p2p.txt"
servers_double = []
servers_double_path = parent_dir + "/servers_double.txt"
servers_onion = []
servers_onion_path = parent_dir + "/servers_onion.txt"
for server in servers_json:
	if len(server["categories"]) > 0:
		if server["categories"][0]["name"] == "P2P":
			servers_p2p.append(server["domain"])
	for name in server["categories"]:
		if name["name"] == "Standard VPN servers":
			#print(name)
			#print(server["domain"])
			servers_standard.append(server["domain"])
		elif name["name"] == "Dedicated IP":
			#print(server["domain"])
			servers_dedicated.append(server["domain"])
		elif name["name"] == "Obfuscated Servers":
			#print(server["domain"])
			servers_obfuscated.append(server["domain"])
		#elif len(server["categories"]) < 2 and name["name"] == "P2P":
			#print(server["domain"])
		#	servers_p2p.append(server["domain"])
		elif name["name"] == "Double VPN":
			#print(server["domain"])
			servers_double.append(server["domain"])
		elif name["name"] == "Onion Over VPN":
			#print(server["domain"])
			servers_onion.append(server["domain"])
print("length servers",len(servers_json))
print("length Standard VPN servers",len(servers_standard))
print("length Dedicated IP",len(servers_dedicated))
print("length Obfuscated Servers",len(servers_obfuscated))
print("length P2P",len(servers_p2p))
print("length Double VPN",len(servers_double))
print("length Onion Over VPN",len(servers_onion))
print("length servers",len(servers_standard)+len(servers_dedicated)+len(servers_obfuscated)+len(servers_double)+len(servers_onion))

"""file.write_list_as_text(servers_standard_path, servers_standard)
file.write_list_as_text(servers_dedicated_path, servers_dedicated)
file.write_list_as_text(servers_obfuscated_path, servers_obfuscated)
file.write_list_as_text(servers_p2p_path, servers_p2p)
file.write_list_as_text(servers_double_path, servers_double)
file.write_list_as_text(servers_onion_path, servers_onion)"""
