#!/usr/bin/python3

import os
import sys
import socket
import struct
import fcntl

from http.server import BaseHTTPRequestHandler, HTTPServer

INDEX_PAGE_FMT = '''
<!doctype html> 
<html>
	<head> <meta charset="utf-8">
		<title>Network IP Address</title>
	</head>
	<body> 
            My IP is: my_ip_here 
            Remote IP is: your_ip_here
        </body>
</html>
'''

def my_ip():
    intfs = os.listdir('/sys/class/net/')
    intfs.remove('lo')
    if len(intfs) == 0:
        return 'N/A'
    SIOCGIFADDR = 0x8915
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack('256s', intfs[0][:15].encode('utf-8')))[20:24])

class S(BaseHTTPRequestHandler):
    def do_GET(self):
        local_ip = my_ip()
        remote_ip = self.client_address[0]

        page = INDEX_PAGE_FMT.replace('my_ip_here', local_ip).replace('your_ip_here', remote_ip)

        self.send_response(200)
        encoding = sys.getfilesystemencoding()
        self.send_header("Content-type", "text/html; charset=%s" % encoding)
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()

        self.wfile.write(page.encode('utf-8'))

def run(server_class=HTTPServer, handler_class=S, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()

if __name__ == '__main__':
    run()
