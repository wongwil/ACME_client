from flask import Flask
import threading
import logging

PORT =  5001 # Certificate HTTPS Server: should run on TCP Port 5001


class CertificateHttpsServer:
    def __init__(self):
        self.app  = Flask(__name__)
        logging.getLogger('werkzeug').setLevel(logging.ERROR) # disable output exxcept errors
        
        @self.app.route('/', methods=['GET', 'HEAD'])
        def route():
            return "Hello William! This is your HTTPS Server"

    def start(self, ssl_context=None):        
        server_thread = threading.Thread(target=self._run_server, args=(ssl_context,), daemon=True)
        server_thread.start()
        print('STARTING HTTPS SERVER')
        #  ssl_context=("localhost.crt", "localhost-privateKey.key")
        #self.app.run(host='0.0.0.0', port=PORT, ssl_context=ssl_context)

    def _run_server(self, ssl_context):
        print(f"HTTPS CERTIFICATE SERVER STARTED ON PORT: {PORT}")
        print(ssl_context)
        self.app.run(host='0.0.0.0', port=PORT, ssl_context=ssl_context)

