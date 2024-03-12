# standard lib
import argparse 
import threading
import time
import os
import ssl
# whitelists
#from flask import Flask, request
import flask
from flask import Flask
import requests

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives import serialization
# classes
from client import Client
from dns import SimpleDNSServer
from certificate_httpsserver import CertificateHttpsServer
from shutdown_httpserver import ShutdownHttpServer
from challenge_httpserver import ChallengeHttpServer

def start_ACME_protocol(args):
    '''https_server = CertificateHttpsServer()
    https_server.start(ssl_context=("certificate.pem", "private_key.pem")) # https://127.0.0.1:10053/

    #app.run(debug=True, port=10053, ssl_context=("cert.pem", "key.pem"))'''

    shutdown_httpserver = ShutdownHttpServer()

    shutdownserver_thread = threading.Thread(target=shutdown_httpserver._run_server) # main waits for T1 to end
    shutdownserver_thread.start()
    
    dns_server = SimpleDNSServer()
    challenge_http_server = ChallengeHttpServer()

    for domain in args.domain:
        dns_server.add_address_record(domain, args.record)

    dns_server.start_server()
    challenge_http_server.start_server()

    client = Client(dir_url=args.dir, dns_server=dns_server, http_challenge_server=challenge_http_server)
    print(client.private_key)

    
    success = client.request_account()


    # Once an account is registered, there are four major steps the client needs to take to get a certificate: 
    # 1.  Submit an order for a certificate to be issued 
    # 2.  Prove control of any identifiers requested in the certificate 
    # 3.  Finalize the order by submitting a CSR 
    # 4.  Await issuance and download the issued certificate
    if success:
        success = client.apply_certificate_issuance(identifiers=args.domain, challenge_choice=args.challenge_type)
    else:
        # account cannot be registered
        print('Account cannot be registered. Stopping DNS server.')
        dns_server.stop_server()

    if success == True:
        private_key, certificate_downloaded = client.download_certificate()
        ssl_context = write_certificate_files(private_key, certificate_downloaded)

        
        # start certificate HTTPS server
        https_server = CertificateHttpsServer()
        # TODO REMOVE
        #ssl_context = ('cert.pem', 'key.pem') # self signed signature for testing

        https_server.start(ssl_context=ssl_context)


        # test
        #response = requests.head("http://127.0.0.1:10053/", verify=False)
        '''
        response = requests.head('https://127.0.0.1:10053/', verify='pebble.minica.pem')
        if response.status_code == 200:
            print('HTTPS SERVER SUCCESS')
        else: 
            print('HTTPS Request failed')
            print(response.json())
        
        '''
        if args.revoke:
            client.revoke_certificate()
   
   
    shutdownserver_thread.join() # wait until shutdown thread is ended
    dns_server.stop_server()



def write_certificate_files(private_key : RSAPrivateKey, certificate):
    current_script_parent_path = os.path.dirname(os.path.abspath(__file__))

    key_path = os.path.join(current_script_parent_path, "private_key.pem")

    certificate_path = os.path.join(current_script_parent_path, "certificate.pem")

    with open(key_path, 'wb') as key_file:
        key_file.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, 
                                                 format=serialization.PrivateFormat.TraditionalOpenSSL, 
                                                 encryption_algorithm=serialization.NoEncryption()
                                                 ))
        

    with open(certificate_path, 'wb') as certificate_file:
        certificate_file.write(certificate)

    #ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) 
    #ssl_context.load_cert_chain(certificate_path, key_path)
    ssl_context = (certificate_path, key_path)         

    return ssl_context

    
# ./project/run dns01 --dir https://localhost:14000/dir --record 1.2.3.4 --domain netsec.ethz.ch --domain syssec.ethz.ch
def main():
    print("....Let's start!")

    # arguments (-- are optional)
    parser = argparse.ArgumentParser()
    parser.add_argument("challenge_type", choices=['dns01', 'http01'])
    parser.add_argument("--dir", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--domain", action="append", required=True)
    parser.add_argument("--revoke", action="store_true")
    args = parser.parse_args()

    start_ACME_protocol(args)

    


if __name__  == '__main__':
    main()