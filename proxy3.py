import argparse
import http.client
import http.server
import select
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

RED = 31
GREEN = 32
YELLOW = 33
BLUE = 34
MAGENTA = 35
CYAN = 36


def with_color(c: int, s: str):
    return "\x1b[%dm%s\x1b[0m" % (c, s)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        # suppress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        super().__init__(*args, **kwargs)

    def log_error(self, format, *args):
        # suppress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        host, _ = self.path.split(":", 1)

        print("HTTPS relay only, NOT Intercepting...")
        self.connect_relay()

    def connect_relay(self):
        address = self.path.split(":", 1)
        address = (address[0], int(address[1]) or 443)
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception:
            self.send_error(502)
            return
        self.send_response(200, "Connection Established")
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = False
        print("address", address)
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = True
                    break
                other.sendall(data)

    def do_GET(self):
        req = self
        content_length = int(req.headers.get("Content-Length", 0))
        req_body = self.rfile.read(content_length) if content_length else b""

        if req.path[0] == "/":
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers["Host"], req.path)
            else:
                req.path = "http://%s%s" % (req.headers["Host"], req.path)

        u = urllib.parse.urlsplit(req.path)
        scheme = u.scheme
        netloc = u.netloc
        path = u.path + "?" + u.query if u.query else u.path
        assert scheme in ("http", "https")
        if netloc:
            req.headers["Host"] = netloc
        req.headers = self.filter_headers(req.headers)

        origin = (scheme, netloc)
        res, res_body = self.request_handler(origin, req, req_body)

        res_headers = self.filter_headers(res.headers)
        self.send_response(res.status, res.reason)
        for header, value in res_headers.items():
            self.send_header(header, value)
        self.end_headers()

        self.wfile.write(res_body)

        self.log_info(req, res)

    def request_handler(self, origin, req, req_body):
        if origin not in self.tls.conns:
            self.tls.conns[origin] = self.create_connection(origin)
        conn = self.tls.conns[origin]

        headers = dict(req.headers)
        headers.pop("Proxy-Connection", None)

        conn.request(req.command, req.path, req_body, headers)

        res = conn.getresponse()
        res_body = res.read()

        return res, res_body

    def create_connection(self, origin):
        scheme, netloc = origin
        if scheme == "https":
            return http.client.HTTPSConnection(netloc)
        return http.client.HTTPConnection(netloc)

    def filter_headers(self, headers):
        headers = dict(headers)
        headers.pop("Proxy-Connection", None)
        headers.pop("Proxy-Authorization", None)
        return headers

    def log_info(self, req, res):
        print(with_color(YELLOW, req.requestline))
        print(with_color(CYAN, "Host: %s" % req.headers["Host"]))
        print(with_color(GREEN, "Response: %d %s" % (res.status, res.reason)))
        print()

    def log_message(self, format, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=12345, help="proxy port")
    args = parser.parse_args()

    server = ThreadingHTTPServer(("0.0.0.0", args.port), ProxyRequestHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
