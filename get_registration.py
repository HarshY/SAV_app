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
    # Send query to server
    query_url_bytes = bytes(query_url, encoding="utf-8")
    sock.send(query_url_bytes + b"\r\n")

    # Collect response from server into one string and return
    final_response_arr = bytearray()
    tmp = sock.recv(128)
    final_response_arr.extend(tmp)
    while tmp:
        tmp = sock.recv(128)
        final_response_arr.extend(tmp)
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
            break
    if(expiry_string == ""):
        return ""
    expiry_date_time = expiry_string.split(": ")[1]
    expiry_date = parseDate(expiry_date_time)
    return expiry_date

'''
    Takes in ip address or url as user input and returns domain
    Inputs:
        user_input: User given ip address or url
    Output:
        domain
'''
def getDomain(user_input):
    url = ""
    # Check if ip address
    try:
        ipaddress.ip_address(user_input)
        url = socket.gethostbyaddr(user_input)[0]
    except ValueError:
        url = user_input

    # Remove scheme, path, etc. from url
    if(url.find("//") >= 0):
        url = url.split("//")[1] #Remove everything before //
    if(url.find("/") >= 0):
        url = url.split("/")[0] #Remove everything after first /
    url_split = url.split(".")

    # Find TLD and final domain
    final_domain = ""
    tld_file = open("./tld_list.txt", encoding="utf-8")
    tld_list = set(tld_file.read().splitlines())
    for i in range(0, len(url_split)):
        if(final_domain != ""):
            final_domain = "." + final_domain
        curr_part = url_split[len(url_split) - 1 - i]
        final_domain = curr_part + final_domain
        if(final_domain not in tld_list):
            break
    return final_domain

'''
    Takes in a domain name and attempts to return expiration date
    Input:
        domain_name: user given url or ip address
    Output:
        Expiration date if found
'''
def getRegistration(domain_name):
    whois_servers = ["whois.verisign-grs.com", "whois.pir.org"]
    whois_port = 43
    expiry_date = ""
    for server in whois_servers:
        sock = initConnection(server, whois_port)
        final_response = getResponse(domain_name, sock)
        expiry_date = extractExpiryDate(final_response)
        if(expiry_date != ""):
            break
    return expiry_date