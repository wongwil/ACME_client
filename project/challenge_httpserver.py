from flask import Flask, request, Response
import threading
import os
import logging

PORT =  5002 # Challenge HTTP Server: should run on TCP Port 5002


class ChallengeHttpServer:
    def __init__(self):
        self.app  = Flask(__name__)
        self.token_hashmap = {}

        logging.getLogger('werkzeug').setLevel(logging.ERROR) # disable output except errors
        
        @self.app.get('/.well-known/acme-challenge/<token>')
        def check_token(token):
            print(f'CHECKING TOKEN {token}')
            if token in self.token_hashmap:
                key_auth = self.token_hashmap[token]
                return Response(key_auth, mimetype="application/octet-stream")
    
    def start_server(self):
        server_thread = threading.Thread(target=self._run_server, daemon=True)
        server_thread.start()

    def _run_server(self):
        print(f"CHALLENGE HTTP SERVER STARTED ON PORT: {PORT}")
        self.app.run(host='0.0.0.0', port=PORT)

    def register_token(self,token, key_authorization):
        self.token_hashmap[token] = key_authorization
        print(f'TOKEN {token} REGISTERED WITH {key_authorization} ')

