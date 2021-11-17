#!/usr/bin/python3
import socket
import sys
import ssl
from html.parser import HTMLParser

csrftoken = ""
username = ""
password = ""
csrfmiddlewaretoken = ""
nextt = ""

csrfmiddle = ''

comp = ""
flags = set()
comps = set()
history = set()
frontier = set()

mock_links_3 = {
    '1' : '<a href=\"2\">mock</a>',
    '2' : '<a href=\"3\">mock</a>\r\n<a href=\"4\">mock</a>',
    '3' : '<a href=\"5\">mock</a>\r\n<a href=\"1\">mock</a>\r\n<a href=\"2\">mock</a>\r\n<a href=\"8\">mock</a>',
    '4' : '<a href=\"17\">mock</a>\r\n<a href=\"10\">mock</a>\r\n<a href=\"11\">mock</a>',
    '5' : '<a href=\"3\">mock</a>\r\n<a href=\"4\">mock</a>',
    '6' : '<a href=\"1\">mock</a>\r\n<a href=\"13\">mock</a>',
    '7' : '<a href=\"3\">mock</a>\r\n<h2 class=\'secret_flag\' style=\"color:red\">FLAG: Got_7</h2>\r\n<a href=\"2\">mock</a>',
    '8' : '<a href=\"12\">mock</a>\r\n<a href=\"9\">mock</a>',
    '9' : '<a href=\"7\">mock</a>\r\n<a href=\"8\">mock</a>',
    '10' : '<a href=\"9\">mock</a>\r\n<a href=\"10\">mock</a>',
    '11' : '<a href=\"3\">mock</a>\r\n<a href=\"6\">mock</a>',
    '12' : '<h2 class=\'secret_flag\' style=\"color:red\">FLAG: Got_12</h2>\r\n<a href=\"1\">mock</a>',
    '13' : '<h2 class=\'secret_flag\' style=\"color:red\">FLAG: Got_13</h2>\r\n<a href=\"3\">mock</a>\r\n<a href=\"6\">mock</a>',
    '14' : '<a href=\"20\">mock</a>\r\n<a href=\"15\">mock</a>',
    '15' : '<a href=\"16\">mock</a>\r\n<a href=\"18\">mock</a>',
    '16' : '<h2 class=\'secret_flag\' style=\"color:red\">FLAG: Got_16</h2>',
    '17' : '<a href=\"14\">mock</a>\r\n<a href=\"16\">mock</a>',
    '18' : '<a href=\"19\">mock</a>\r\n<a href=\"5\">mock</a>',
    '19' : '<h2 class=\'secret_flag\' style=\"color:red\">FLAG: Got_19</h2>',
    '20' : '<a href=\"1\">mock</a>\r\n<a href=\"2\">mock</a>',
}

mock_start_3 = '<a href=\"1\">mock</a>'

mock_csrf = '<input type="hidden" name="csrfmiddlewaretoken" value="zeVpBxYQf2FA3XLPXBOXn6k03urJ2SXK3QW7SJ5IigjiVym9NSSXw9cupy0RdvGp">'

class parserGET(HTMLParser):
    def handle_starttag(self, tag, attrs):
        print("Encountered a start tag:", tag)

class MyHTMLParser(HTMLParser):

    def handle_starttag(self, tag, attrs):
        global comp,csrfmiddle

        if tag == 'a' or tag == 'h2':
            comp += f'<{tag}>'
            for at in attrs:
                comp += str(at) + " "
            if tag == 'a':
                if attrs[0][1] not in history:
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
                flags.add(f_split[1])
            comp += data
        # print("Encountered some data  :", data)

# takes html element and crawls it, as well as links inside it
def process_html(html):
    parser = MyHTMLParser()
    parser.feed(html)

    #loop for next html
    while len(frontier) > 0:
        link = frontier.pop()

        # this will need to be replaced with our GET method.
        # need to return an html string from the response.
        next_html = mock_links_3[link]

        history.add(link)
        process_html(next_html)


#create a socket to the host on the https port
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    s = ssl.wrap_socket(sock) 
    s.connect(("fakebook.3700.network", 443))
    s.getsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

"""
if( x == 0):
            print 'Socket Keepalive off, turning on'
            x = sock.setsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            print 'setsockopt=', x
        else:
            print 'Socket Keepalive already on'
"""

#do a GET request for the homepage
# @@@@ fakebook.3700.network/
request = "GET /accounts/login/?next=/fakebook/ HTTP/1.0\r\n\r\n"
s.sendall(bytes(request, 'utf-8'))
#s.send(request.encode()) #@@@@@ when do you implement keep alive??

#recive the answer from the GET
resp = s.recv(4096).decode('utf-8') 
# print(response)

#send POST request to login
pRequest = "POST /accounts/login/ HTTP/1.0"
parser = parserGET()
# parser.feed(response)

def process_response(response):
    split_response = response.split("\r\n\r\n\n\n\n")
    header = split_response[0]
    html = split_response[1]
    split_header = header.split("\r\n")

    header_dict = {}
    for item in split_header:
        if 'HTTP/1.1 ' in item:
            sp = item.split(' ')
            header_dict['status'] = sp[1]
        else:
            sp = item.split(': ')
            header_dict[sp[0]] = sp[1]
    return header_dict, html

my_header, my_html = process_response(resp)

cookie = my_header['Set-Cookie'].split()[0][:-1]

parser = MyHTMLParser()
parser.feed(my_html)

print(cookie)



# print(csrfmiddle)
# print(frontier)