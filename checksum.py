#!/usr/bin/env python3
__version__ = "1.1"
#https://www.quickprogrammingtips.com/python/how-to-calculate-md5-hash-of-a-file-in-python.html
"""
# Python program to find MD5 hash value of a file
import hashlib
filename = input("Enter the file name: ")
with open(filename,"rb") as f:
	bytes = f.read() # read file as bytes
	readable_hash = hashlib.md5(bytes).hexdigest();
	print(readable_hash)
"""
# Python program to find MD5 hash value of a file, capable of handling large files
import hashlib
import pathlib
import sys
import utility
print("Enter the path of file name.")
if len(sys.argv) != 2:
	print(f'{utility.Clr.YELLOW2}usage:{utility.Clr.RST2} {utility.Clr.YELLOW}{sys.argv[0]} {utility.Clr.BLUE}192.168.88.1.pub{utility.Clr.RST}')
	sys.exit(1)
else:
	try:
		remotepath = pathlib.Path(sys.argv[1])
		if remotepath.exists():
			print(utility.Clr.YELLOW + str(remotepath) + utility.Clr.RST)
			md5_hash = hashlib.md5()
			with open(remotepath,"rb") as f:
				# Read and update hash in chunks of 4K
				for byte_block in iter(lambda: f.read(4096),b""):
					md5_hash.update(byte_block)
				print("md5 hash", utility.Clr.BLUE + remotepath.name + utility.Clr.RST + ":", utility.Clr.YELLOW2 + md5_hash.hexdigest() + utility.Clr.RST2)
		else:
			("False existing file:",remotepath)
			sys.exit(1)
	except Exception as error:
		print("failed")
		print(error)
