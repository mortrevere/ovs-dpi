#! /usr/bin/python3.4

import socket
import sys
import redis
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
print(r.set('foo', 'bar'))
print(r.get('foo'))

PROTO = {'80' : 'http', '443' : 'https', '53' : 'dns'}
HOST_NAME = '10.206.19.154'
PORT_NUMBER = 9000

class DPIDataEngine():
    def __init__(self):
        self.update()
        self.toJSON()

    def update(self):
        self.dpi_data = r.hgetall('dpi')
        self.dns_cache = r.hgetall('dns') #dns lookups made after ip addresses
        self.qdns_data = r.hgetall('qdns') #dns queries
        self.toJSON()

    def toJSON(self):
        o = {}
        for key, value in self.dpi_data.items():
            s = key.split('->')
            source = s[0]
            dest_and_port = s[1].split(':')
            dest = dest_and_port[0]
            port = dest_and_port[1]
            o.setdefault(source, [])
            o[source] += [{'dest' : { 'ip' : dest, 'host' : self.DNSbestGuess(dest), 'port' : port}, 'vol' : int(self.dpi_data[key])}]
            if o[source][-1]['dest']['ip'] == o[source][-1]['dest']['host'][0]:
                o[source].pop()
        self.o = o;
        return o

    def baseDomain(self, domain):
        return domain
        subs = domain.split('.')
        return '.'.join(subs[-2:])

    def DNSbestGuess(self, ip):
        guesses = []
        if ip in self.qdns_data.keys():
            guesses += [self.baseDomain(self.qdns_data[ip])]
        if ip in self.dns_cache.keys():
            guesses += [self.baseDomain(self.dns_cache[ip])]
        if len(guesses) == 0:
            guesses += [ip]
        return guesses

    def toChartJS(self, protocol):
        labels = []
        data = []
        if protocol[0:4] == 'http':
            for source, d in self.o.items():
                for value in d:
                    if type(value) is not int and PROTO[value['dest']['port']] == protocol:
                    #print(value)
                        labels += [value['dest']['host'][0]]
                        data += [value['vol']]
        elif protocol == 'dns':
            for ip, domain in self.qdns_data.items():
                labels += [domain]
                data += [1]

        return {'labels' : labels, 'data' : data}



e = DPIDataEngine();
#print(e.toChartJS())

class HTTPHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

    def do_GET(self):
        self.respond({'status': 200})

    def handle_http(self, status_code, path):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        e.update()
        return bytes(json.dumps(e.toChartJS(path[1:])), 'UTF-8')

    def respond(self, opts):
        response = self.handle_http(opts['status'], self.path)
        self.wfile.write(response)

if __name__ == '__main__':
    server_class = HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), HTTPHandler)
    print(time.asctime(), 'Server Starts - %s:%s' % (HOST_NAME, PORT_NUMBER))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
print(time.asctime(), 'Server Stops - %s:%s' % (HOST_NAME, PORT_NUMBER))
