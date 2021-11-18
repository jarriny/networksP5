#!/usr/bin/python3
import socket
import sys
import ssl
import time
from html.parser import HTMLParser

import datetime

csrftoken = ''

# username = "jarrin.y"
# password = "ZDPZ6OOA7MNCW512"

args = sys.argv
length = len(args)

username = args[1]
password = args[2]
#print("username : " + username + "password: " + password)

#username = "hill.bri"
#password = "QYHNOH9FA44LSQ12"

nextt = "%2Ffakebook%2F"
csrfmiddle = ''

comp = ""
flags = set()
comps = set()
history = set()
frontier = set()
csrftoken = ""
sessionid = ""
cookie = ""
crash_cnt = 0

start = ''
end = ''

class MyHTMLParser(HTMLParser):

    def handle_starttag(self, tag, attrs):
        global comp,csrfmiddle

        if tag == 'a' or tag == 'h2':
            comp += f'<{tag}>'
            for at in attrs:
                comp += str(at) + " "
            if tag == 'a':
                if attrs[0][1] not in history and '/fakebook/' in attrs[0][1]:
                    frontier.add(attrs[0][1])
        elif tag == 'input':
            if attrs[1][1] == 'csrfmiddlewaretoken':
                csrfmiddle = attrs[2][1]
        # print("Encountered a start tag:", tag, attrs)
        
    def handle_endtag(self, tag):
        global comp
        if comp != "":
            comp += f'<{tag}>'
            comps.add(comp)
            comp = ""
        # print("Encountered an end tag :", tag)

    def handle_data(self, data):
        global comp
        if comp != "":
            if "secret_flag" in comp:
                flag = data
                f_split = flag.split(": ")
                # print(flag)
                flags.add(f_split[1])
                if len(flags) >= 5:
                    end = datetime.datetime.now()
                    for f in flags:
                        print(f)

                    # print(start,":", end)
                    print(end - start)
                    print("Crashed", crash_cnt, "times.")
                    exit(0)
            comp += data
        # print("Encountered some data  :", data)

# takes html element and crawls it, as well as links inside it
def process_html(html):
    global cookie

    parser = MyHTMLParser()
    parser.feed(html)

    #loop for next html
    while len(frontier) > 0:
        
        link = frontier.pop()
        history.add(link)

        # this will need to be replaced with our GET method.
        # need to return an html string from the response.
        resp = get_request(link, cookie)
        if('Transfer-Encoding: chunked' in resp):
            t = ""
        # print(link)
        # print('**********************************')
        # print(resp)
        # print("----------------------------------")
        if resp == "":
            print("Something went wrong")
            print(link)
            print(flags)
            sock
            break
        
        next_header, next_html = process_response(resp)
        try:
            if next_header['status'] != '200':
                print(next_header['status'])
        except:
            print(resp)
        cookie = build_cookie()
        parser.feed(next_html)

        # process_html(next_html)

        
def process_response(response):
    global csrftoken
    global sessionid
    split_response = response.split("\r\n\r\n\n\n\n")
    header = split_response[0]
    try:
        html = split_response[1]
    except:
        html = ""
    split_header = header.split("\r\n")

    header_dict = {}
    for item in split_header:
        if 'HTTP/1.1 ' in item:
            sp = item.split(' ')
            header_dict['status'] = sp[1]
        elif item != "":
            sp = item.split(': ')
            if sp[0] == 'Set-Cookie':
                if 'csfrtoken=' in sp[1]:
                    csrftoken = sp[1]
                elif 'sessionid=' in sp[1]:
                    sessionid = sp[1]
            header_dict[sp[0]] = sp[1]
    return header_dict, html

def build_cookie():

    c1_split = csrftoken.split()
    c2_split = sessionid.split()

    cookie = c1_split[0] + '; ' + c2_split[0]
    return cookie[:-1]


def get_request(url, cookie):
    global s, crash_cnt
    resp = ""
    cnt = 0
    while resp == "" and not (cnt > 10):
        if cnt > 1:
            time.sleep(5)
        request = f"GET {url} HTTP/1.1\r\nConnection: keep-alive\r\nCookie: {cookie}\r\nHost: fakebook.5700.network\r\n\r\n"
        # print(request)
        try:
            s.sendall(bytes(request, 'utf-8'))
        except:
            crash_cnt += 1
            s.close()
            # print("closed")
            time.sleep(10)
            # print("trying to reopen")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                s = ssl.wrap_socket(sock) 
                s.connect(("fakebook.3700.network", 443))
                s.getsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 30)
            try:
                s.sendall(bytes(request, 'utf-8'))
                # print("success!")
            except:
                print("Broke Twice")
                exit(1)


        # recieve the response
        resp = s.recv(4096).decode('utf-8')
        cnt += 1

    if cnt > 10:
        print("Aborting")
        print(request)
    return resp
        
#create a socket to the host on the https port
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    s = ssl.wrap_socket(sock) 
    s.connect(("fakebook.3700.network", 443))
    s.getsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 30)

start = datetime.datetime.now()

#do a GET request for the homepage
# @@@@ fakebook.3700.network/
request = "GET /accounts/login/?next=/fakebook/ HTTP/1.1\r\nConnection: keep-alive\r\nHost: fakebook.5700.network\r\n\r\n"
s.sendall(bytes(request, 'utf-8'))

#recive the answer from the GET
resp = s.recv(4096).decode('utf-8') 
# print(resp)


my_header, my_html = process_response(resp)

try:
    csrftoken = my_header['Set-Cookie'].split()[0][:-1]
except:
    print(my_header)
    print(resp)

parser = MyHTMLParser()
parser.feed(my_html)

# print("the csrf token we found: " + str(csrftoken))
# print("the csrfmiddle token we found" + str(csrfmiddle))

postStuff = "Host: fakebook.3700.network\r\n" + "Connection: keep-alive\r\n" + "Content-Length: 148\r\n" + "Cache-Control: max-age=0\r\n"
postStuff += "sec-ch-ua: \"Google Chrome\";v=\"95\", \"Chromium\";v=\"95\", \";Not A Brand\";v=\"99\"\r\n"
postStuff += "sec-ch-ua-mobile: ?0\r\n" + "sec-ch-ua-platform: \"Windows\"\r\n" + "Upgrade-Insecure-Requests: 1\r\n"
postStuff += "Origin: https://fakebook.3700.network\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n"
postStuff += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36\r\n"
postStuff += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
postStuff += "cp-extension-installed: Yes\r\n" + "Sec-Fetch-Site: same-origin\r\n" + "Sec-Fetch-Mode: navigate\r\n" + "Sec-Fetch-User: ?1\r\n"
postStuff += "Sec-Fetch-Dest: document\r\n" + "Referer: https://fakebook.3700.network/accounts/login/?next=/fakebook/\r\n"
postStuff += "Accept-Encoding: gzip, deflate, br\r\n" + "Accept-Language: en-US,en;q=0.9,fr;q=0.8\r\n"


cookieText = "Cookie: " + csrftoken + "\r\n\r\n"
# added the \r\n\r\n becuase I think what comes next is the body
userPassToken = "username=" + username + "&password=" + password + "&csrfmiddlewaretoken=" + csrfmiddle + "&next=" + nextt + "\r\n\r\n"

#send POST request to login
pRequest = "POST /accounts/login/ HTTP/1.1\r\n"
pRequest += postStuff
pRequest += cookieText
pRequest += userPassToken

# print("pRequest :" + pRequest)

#send the POST to login
s.sendall(bytes(pRequest, 'utf-8'))

#what received after loggin in
resp = s.recv(4096).decode('utf-8')
# print("what received after login in" + resp)

my_header, my_html = process_response(resp)

cookie = build_cookie()

url = '/fakebook/'

resp = get_request(url, cookie)

my_header, my_html = process_response(resp)
cookie = build_cookie()
process_html(my_html)

# print(frontier)
