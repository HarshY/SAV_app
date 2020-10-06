import os
import socket

'''
    Initializes connection to whois server
    Inputs:
        serv_domain: (String) domain pf whois server
        serv_port: Port to send request to (43)
    Out
'''
def init_connection(serv_domain, serv_port):
    sock = socket.socket(socket.AF_INET)
    serv_addr = (serv_domain, serv_port)
    sock.connect(serv_addr)
    print("connected")
    return sock

'''
    Takes url of query domain and returns full server response from whois
    Inputs:
        query_url: (String) url of user input domain
        sock: (Socket) socket connection 
    Output:
        full response of server as string
'''
def get_response(query_url, sock):
    query_url_bytes = bytes(query_url, encoding="utf-8")
    sock.send(query_url_bytes + b"\r\n")
    print("sent")

    final_response_arr = bytearray()
    tmp = sock.recv(128)
    final_response_arr.extend(tmp)
    while tmp:
        tmp = sock.recv(128)
        final_response_arr.extend(tmp)
    print("received")
    return final_response_arr.decode(encoding="utf-8")

'''
    Takes full server response and returns the expiry date
    Inputs:
        final_response: (String) response from server
    Output:
        expiry date as string
'''
def extract_expiry_date(final_response):
    response_lines = final_response.splitlines()
    expiry_string = ""
    for single_line in response_lines:
        if(single_line.find("Expiry") >= 0):
            expiry_string = single_line
            break
    if(expiry_string == ""):
        return ""
    expiry_date_time = expiry_string.split(": ")[1]
    expiry_date = expiry_date_time.split("T")[0]
    print(expiry_date)
    return expiry_date

def get_registration():
    sock = init_connection("whois.verisign-grs.com", 43)
    query_url = "weather.com"
    final_response = get_response(query_url, sock)
    expiry_date = extract_expiry_date(final_response)

def main():
    get_registration()

if __name__ == "__main__":
    main()