import socket
req = "DESCRIBE rtsp://192.168.31.110:554 RTSP/1.0\r\nCSeq: 2\r\n\r\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.31.110", 554))
s.sendall(req)
data = s.recv(1024)
print data