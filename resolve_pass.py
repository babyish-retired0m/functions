#!/usr/bin/env python3
try:
	from icmplib import resolve
except ImportError:
    raise SystemExit("Please install icmplib, pip3 install icmplib (https://github.com/ValentinBELYN/icmplib)")
    
address="peg.a2z.com"
address="amazon.com"
try:
	ip_address = resolve(address)
	print(f"The name '{address}' resolved {ip_address}")
except:
	print(f"The name '{address}' cannot be resolved")
