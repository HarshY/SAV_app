import os
import socket

# Initialize socket
sock = socket.socket(socket.AF_INET)
#input_domain = input()
#input_domain = "www.weather.com"

# Connect to whois server
#print(socket.gethostbyaddr(input_domain))
serv_addr = ("whois.verisign-grs.com", 43)
sock.connect(serv_addr)
print("connected")

# Send query to whois server
query_address = "weather.com"
final_response = b""
sock.send(bytes(query_address, "utf-8") + b"\r\n")
print("sent")

# Receive bytes from whois server
tmp = sock.recv(128)
final_response += tmp
while tmp:
    tmp = sock.recv(128)
    final_response += tmp
print("received")
print(final_response)
sock.close()