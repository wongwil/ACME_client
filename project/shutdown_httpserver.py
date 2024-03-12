from flask import Flask, request
import threading
import os
import logging

PORT =  5003 # Certificate HTTPS Server: should run on TCP Port 501

class ShutdownHttpServer:
    def __init__(self):
        self.app  = Flask(__name__)
        logging.getLogger('werkzeug').setLevel(logging.ERROR) # disable output except errors
        
        @self.app.route('/')
        def hello():
            return "Hello William! This is your Shutdown Server"
        
        @self.app.get('/shutdown')
        def shutdown():
            print("Stopping whole application...")  
            os._exit(0)


    def _run_server(self):
        print(f"starting shutdown server on Port: {PORT}")
        self.app.run(host='0.0.0.0', port=PORT)

