import os
import socket
from datetime import datetime
import ipaddress

'''
    Initializes connection to whois server
    Inputs:
        serv_domain: (String) domain pf whois server
        serv_port: Port to send request to (43)
    Out
'''
def initConnection(serv_domain, serv_port):
    sock = socket.socket(socket.AF_INET)
    serv_addr = (serv_domain, serv_port)
    sock.connect(serv_addr)
    #print("connected")
    return sock

def parseDate(date_string):
    # Common date and time formats on server
    date_format = ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ", "%Y/%m/%d", 
        "%Y/%m/%d %H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"]

    # Convert to datetime object
    for f in date_format:
        try:
            date = datetime.strptime(date_string, f)
            return date
        except ValueError:
            pass
            #print(f"{f} didn't work")
    return None

'''
    Takes url of query domain and returns full server response from whois
    Inputs:
        query_url: (String) url of user input domain
        sock: (Socket) socket connection 
    Output:
        full response of server as string
'''
def getResponse(query_url, sock):
    query_url_bytes = bytes(query_url, encoding="utf-8")
    sock.send(query_url_bytes + b"\r\n")
    #print("sent")

    final_response_arr = bytearray()
    tmp = sock.recv(128)
    final_response_arr.extend(tmp)
    while tmp:
        tmp = sock.recv(128)
        final_response_arr.extend(tmp)
    #print("received")
    return final_response_arr.decode(encoding="utf-8")

'''
    Takes full server response and returns the expiry date
    Inputs:
        final_response: (String) response from server
    Output:
        expiry date as string
'''
def extractExpiryDate(final_response):
    response_lines = final_response.splitlines()
    expiry_string = ""
    for single_line in response_lines:
        single_lower = single_line.lower()
        #print(single_lower.find("registry expiry date:") >= 0)
        if(single_lower.find("expiration date:") >= 0 or 
            single_lower.find("expires on:") >= 0 or
            single_lower.find("registry expiry date:") >= 0 or
            single_lower.find("expires:") >= 0 or
            single_lower.find("expiry date:") >= 0 or
            single_lower.find("renewal date:") >= 0 or
            single_lower.find("registration expiration date:") >= 0 or
            single_lower.find("record expires on:") >= 0 or
            single_lower.find("domain expiration date:") >= 0):
            expiry_string = single_line
            #print("test")
            break
    #print(f"expiry string is: {expiry_string}")
    if(expiry_string == ""):
        return ""
    expiry_date_time = expiry_string.split(": ")[1]
    #print(expiry_date_time)
    expiry_date = parseDate(expiry_date_time)
    #print(expiry_date)
    return expiry_date

'''
'''
def getDomain(user_input):
    url = ""
    try:
        ipaddress.ip_address(user_input)
        url = socket.gethostbyaddr(user_input)[0]
    except ValueError:
        url = user_input
    #print(url)
    if(url.find("//") >= 0):
        url = url.split("//")[1] #Remove everything before //
    if(url.find("/") >= 0):
        url = url.split("/")[0] #Remove everything after first /
    url_split = url.split(".")
    domain = ""
    tld_file = open("./tld_list.txt", encoding="utf-8")
    tld_list = set(tld_file.read().splitlines())
    for i in range(0, len(url_split)):
        if(domain != ""):
            domain = "." + domain
        curr_part = url_split[len(url_split) - 1 - i]
        domain = curr_part + domain
        if(domain not in tld_list):
            break
    return domain

'''
'''
def getRegistration(domain_name):
    whois_servers = ["whois.verisign-grs.com", "whois.pir.org"]
    whois_port = 43
    expiry_date = ""
    for server in whois_servers:
        #sock = initConnection("whois.verisign-grs.com", 43)
        sock = initConnection(server, whois_port)
        final_response = getResponse(domain_name, sock)
        #print(final_response)
        expiry_date = extractExpiryDate(final_response)
        if(expiry_date != ""):
            break
    return expiry_date