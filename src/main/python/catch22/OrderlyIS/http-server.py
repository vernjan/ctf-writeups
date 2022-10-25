import http.server
import socketserver
from http import HTTPStatus

IP = "10.200.0.11"
PORT = 8000


class LoggingHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):

    def __int__(self):
        super(LoggingHTTPRequestHandler, self).__int__(PORT)

    def do_GET(self):
        self.log_full_request("GET")
        return super(LoggingHTTPRequestHandler, self).do_GET()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])  # <--- Gets the size of data
        post_data = self.rfile.read(content_length)  # <--- Gets the data itself
        self.log_full_request("POST", post_data.decode('utf-8'))
        self.send_response(200)

    def log_full_request(self, method, post_data=""):
        print("{} {}\n\nHeaders:\n{}Body:\n{}\n".format(method, str(self.path), str(self.headers), post_data))

    # To allow CORS
    def do_OPTIONS(self):
        self.send_response(HTTPStatus.OK)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()


Handler = LoggingHTTPRequestHandler

with socketserver.TCPServer((IP, PORT), Handler) as httpd:
    print("Serving at port", PORT)
    httpd.serve_forever()
