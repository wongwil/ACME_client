import requests
import base64
import json
import time
from datetime import datetime, timedelta, timezone

# whitelisted elliptic curve, signature and hash lib
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from dns import SimpleDNSServer
from challenge_httpserver import ChallengeHttpServer

cert_bundle = 'pebble.minica.pem' # force the use of this certificate to establish tls connection

class Client():
    

    def __init__(self, dir_url, dns_server : SimpleDNSServer, http_challenge_server : ChallengeHttpServer):
        self.dir_url = dir_url
        self.dns_server = dns_server
        self.http_challenge_server = http_challenge_server

        self.session =  requests.Session() # create session to save parameters accross HTTP requests
    
        ''' Because client requests in ACME carry JWS objects in the Flattened
        JSON Serialization, they must have the Content-Type header field set
        to "application/jose+json".  If a request does not meet this
        requirement, then the server MUST return a response with status code
        415 (Unsupported Media Type).'''
        headers = {
            "Content-Type": "application/jose+json"
        }

        self.session.headers.update(headers)
        # after request dir url, we get the following urls
        self.new_account_url = None
        self.new_nonce_url = None
        self.new_order_url = None
        self.revoke_cert_url = None

        # after placing new order we get this url
        self.order_url = None

        # after completing challenges and sending validation request, as well as sending the finalize request
        # we get the certificate url
        self.certificate_download_url = None

        # attributes
        #self.nonce = None
        self.account_kid = None # required to sign the jws objects for POST
        self.CSR_key = None
        self.certificate_pem = None

        # keypair and signer
        self.private_key = ECC.generate(curve='P-256')
        self.public_key = self.private_key.public_key()

        self.signer = DSS.new(self.private_key, 'fips-186-3') # signer.sign(...), verifier = DSS.new(public_key, 'fips-186-3'), verifier.verify(message, signature)


    def request_dir_url(self):
        # request from pebble server
        try: 
            directory_response = self.session.get(self.dir_url, verify=cert_bundle) 
            
            # {'keyChange': 'https://localhost:14000/rollover-account-key', 'meta': {'externalAccountRequired': False, 
            # 'termsOfService': 'data:text/plain,Do%20what%20thou%20wilt'}, 'newAccount': 
            # 'https://localhost:14000/sign-me-up', 'newNonce': 'https://localhost:14000/nonce-plz', 
            # newOrder': 'https://localhost:14000/order-plz', 'revokeCert': 'https://localhost:14000/revoke-cert'}

            if directory_response.status_code == 200:
                self.new_account_url = directory_response.json()['newAccount']
                self.new_nonce_url = directory_response.json()['newNonce']
                self.new_order_url = directory_response.json()['newOrder']
                self.revoke_cert_url = directory_response.json()['revokeCert']

                return True
        except:
            print('directory url cannot be requested')
            return False
        

    def request_fresh_nonce(self):
        # request the nonce from url
        nonce_response = self.session.get(self.new_nonce_url, verify=cert_bundle)

        if nonce_response.status_code == 204: # it usually returns 204, and the nonce is in the header
            #print(nonce_response.headers)
            nonce = nonce_response.headers['Replay-Nonce']

            return nonce

    def enc_to_base64(self, data):

        if isinstance(data, str):
            data = bytes(data, 'utf-8')

        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip("=")
    

    # See 8.1 "Key Authorizations" 
    def construct_key_authorization_from_token(self, token):
        # See RFC7638, 3.2 Computing thumbprint of JWK for elliptic curves
        jwk = {
            "crv": "P-256", 
            "kty": "EC",
            "x": self.enc_to_base64(self.public_key.pointQ.x.to_bytes()),
            "y": self.enc_to_base64(self.public_key.pointQ.y.to_bytes())
        }

        jwk_json_utf8 = json.dumps(jwk, separators=(',', ':')) # python obj to json

        # hash the UTF-8 representation with SHA256
        h = SHA256.new()
        h.update(jwk_json_utf8.encode('utf-8'))
        thumprint = h.digest()

        # yay, thumbprint done
        thumbprint_b64 = self.enc_to_base64(thumprint)

        # RFC855: keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))
        key_authorization = token + "." + thumbprint_b64

        return key_authorization
    
    def request_account(self):
        # see 6.2 in RFC8555: protected header includes alg, nonce, url (new account url), kid (key_id) or jwk (mutually exclusive), TODO: we are using jwk for now
        # see 7.3 in RFC 8555: account request includes protected header, payload, signature

        # "An ACME server MUST implement the "ES256" signature algorithm", so we are taking that
        success = self.request_dir_url() # get urls

        if success == False:
            return False

        protected_header = {
            "alg": "ES256",
            "nonce":  self.request_fresh_nonce() ,
            "url": self.new_account_url,
            "jwk": {
                "kty": "EC",
                "crv": "P-256", 
                "x": self.enc_to_base64(self.public_key.pointQ.x.to_bytes()),
                "y": self.enc_to_base64(self.public_key.pointQ.y.to_bytes())
            }
        }
        
        #print(protected_header)

        payload = {
            "termsOfServiceAgreed": True,
            "contact": ["mailto:william@example.org"]
        }

        # see example in 7.3 => protected and payload gotta be in b64
        b64_protected_header = self.enc_to_base64(json.dumps(protected_header))
        b64_payload = self.enc_to_base64(json.dumps(payload))


        # sign the content of protected_header and payload
        # https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
        # See A.3.1. for more info about concatenation, hashing and then signature  
        concatenation = b64_protected_header + "." + b64_payload

        h = SHA256.new()
        h.update(concatenation.encode('utf-8'))

        signature = self.signer.sign(h)
        b64_signature = self.enc_to_base64(signature)

        new_account_json = {
            "protected" : b64_protected_header,
            "payload" : b64_payload,
            "signature": b64_signature
        }
        #print(new_account_json)

        #print(self.new_account_url)
        new_account_response = self.session.post(self.new_account_url, verify=cert_bundle, json=new_account_json)
        #print(new_account_response.json())
        #print(new_account_response.headers)
        #print(new_account_response)
        #print(new_account_response.reason)

        if new_account_response.status_code != 201:
            print('Account creation failed')
            print(new_account_response.json())
            return False
        

        print("** Account successfully requested **")
        ''' The server returns
        this account object in a 201 (Created) response, with the account URL
        in a Location header field.  The account URL is used as the "kid"
        value in the JWS authenticating subsequent requests by this account
        (see Section 6.2).'''
        self.account_kid = new_account_response.headers["Location"]
        print(f"ACCOUNT CREATION KID: {self.account_kid}")
        #print(self.account_kid)
        return True

    # wrap a payload json object into a jws object with header. similar to new account, but with kid.
    # protected: "alg", "kid", "nonce", "url" 
    # signature
    def jws_wrap(self, url, payload):
        protected_header = {
            "alg": "ES256",
            "kid": self.account_kid,
            "nonce": self.request_fresh_nonce(),
            "url": url
        }

        b64_protected_header = self.enc_to_base64(json.dumps(protected_header))
        b64_payload = ""

        if payload != "" :
            b64_payload = self.enc_to_base64(json.dumps(payload))

        concatenation = b64_protected_header + "." + b64_payload

        h = SHA256.new()
        h.update(concatenation.encode('utf-8'))

        signature = self.signer.sign(h)
        b64_signature = self.enc_to_base64(signature)

        jws_wrap = {
            "protected" : b64_protected_header,
            "payload" : b64_payload,
            "signature": b64_signature
        }

        return jws_wrap

    # https://cryptography.io/en/latest/x509/reference/#x-509-csr-certificate-signing-request-object
    def create_CSR(self, domains):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.CSR_key = private_key
        #public_key = private_key.public_key()

        subject_alternative_names = [x509.DNSName(domain) for domain in domains]
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name(
            [x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
             x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "ZH"),
             x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Buelach"),
             x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ETHZ"),
             x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ETHZ-ACME")
             ]
            )).add_extension(x509.SubjectAlternativeName(subject_alternative_names), critical=False)
        
        csr = builder.sign(private_key=private_key, algorithm=hashes.SHA256())

        # According to RFC8555, we need to send it in b64(DER format)
        return csr.public_bytes(serialization.Encoding.DER)


    # See 7.4 Applying for Certificate Issuance, 7.5 Identifier Authorization
    def apply_certificate_issuance(self, identifiers, challenge_choice):
    
        ### ----------- SUBMIT ORDER, See 7.4 -----------------------
        current_date = datetime.now()

        timezone_offset = timezone(timedelta(hours=4))
        current_date = current_date.replace(tzinfo=timezone_offset)
        future_date= current_date + timedelta(days=398) # certificates are usually 398 days valid (Lec 4, Slide 22)

        payload_json = {
            "identifiers" : [{"type": "dns", "value": identifier} for identifier in identifiers],
            "notBefore" : current_date.isoformat(),
            "notAfter": future_date.isoformat()
        }

        new_order_json = self.jws_wrap(self.new_order_url, payload=payload_json)
        new_order_response = self.session.post(self.new_order_url, verify=cert_bundle, json=new_order_json)

        if new_order_response.status_code !=  201:
            print(f"Creating new order failed: {new_order_response.status_code}")
            return False

        authorization_urls = new_order_response.json()['authorizations']
        self.finalize_url = new_order_response.json()['finalize']
        self.order_url = new_order_response.headers['Location']
        #print(new_order_response.json()) 
        print("** Order successfully submitted **")
        #print(new_order_response.json())



        ### ----------- AUTHORIZATION, See 7.5 -----------------------
        challenges = []
        for auth in authorization_urls:
            authorization_json = self.jws_wrap(auth, payload="")
            identifier_auth_response = self.session.post(auth, verify=cert_bundle, json=authorization_json)

            #print(identifier_auth_response.json())
            #print(identifier_auth_response)
            
            if identifier_auth_response.status_code != 200:
                return False
            
            identifier_domain_name = identifier_auth_response.json()['identifier']['value']
            print(f"** Identifier successfully authorized for {identifier_domain_name} **")


            response_challenges = identifier_auth_response.json()['challenges']
            # change argument challenge type to same format as in the response. dns01 -> dns-01, http01 -> http-01
            challenge_choice_json = ""
            if challenge_choice == "dns01":
                challenge_choice_json = "dns-01"
            elif challenge_choice == "http01":
                challenge_choice_json = "http-01"


            # do the challenges
            for challenge in response_challenges:
                if challenge['type'] == challenge_choice_json: # get only challenges that are same as the choice of the argument
                    challenges.append(challenge)
                    # ----------- 8.4.  DNS Challenge -----------
                    if challenge_choice_json == 'dns-01':
                        # See RFC8555, 8.4
                        token = challenge['token']
                        key_authorization = self.construct_key_authorization_from_token(token) # token.thumbprint


                        # we have to hash it again and put the b64 encoding as TXT record under the domain
                        h = SHA256.new()
                        h.update(key_authorization.encode('utf-8'))

                        key_authorization_hashed = h.digest()

                        prepended_domain = "_acme-challenge." + identifier_domain_name

                        self.dns_server.add_txt_record(prepended_domain, rdata=self.enc_to_base64(key_authorization_hashed))

                    elif challenge_choice_json == 'http-01':
                        token = challenge['token']
                        key_authorization = self.construct_key_authorization_from_token(token) # token.thumbprint

                        self.http_challenge_server.register_token(token, key_authorization)


        ### ----------- 7.5.1.  Responding to Challenges -----------------------
        # Telling the server to validate the challenges
        for challenge in challenges:
            payload_json = {} # See 7.5.1, we have to send empty payload {}
            challenge_type = challenge['type']
            print(f'Please validate {challenge_type}')
            challenge_respond_url = challenge['url']
            respond_challenge_json = self.jws_wrap(challenge_respond_url, payload=payload_json)
            respond_challenge_response = self.session.post(challenge_respond_url, verify=cert_bundle, json=respond_challenge_json)

            respond_challenge_response_json = respond_challenge_response.json()
            print("** Validation request successfully sent **")

        
        # Send validation request
        print(authorization_urls)

        for authz_url in authorization_urls:
                poll_json = self.jws_wrap(authz_url, payload="")
                poll_response = self.session.post(authz_url, verify=cert_bundle, json=poll_json)

                #print(poll_response.json())
                if poll_response.status_code == 200:
                    identifier = poll_response.json()['identifier']['value']
                    challenge_state = poll_response.json()["status"]
                    
                    print(f'challenge is in state {challenge_state}. ')
                else: 
                    print(f'validation of challenges failed... status code {poll_response.json()}')


        # check state of order before sending finalize request
        wait_until_finzalize = True

        while(wait_until_finzalize):
            poll_json = self.jws_wrap(self.order_url, payload="")
            poll_response = self.session.post(self.order_url, verify=cert_bundle, json=poll_json)
            if poll_response.status_code == 200:
                    order_state = poll_response.json()["status"]
                    if order_state == 'invalid':
                        print("Invalid order. process abandoned")
                        return False
                    elif order_state == 'pending':
                        print("Pending state, client has not fullfilled the requirements. Let's wait 3 seconds and ask again.")
                        time.sleep(5)
                    elif order_state == 'ready':
                        print("order is READY, pls send a finalization request!")
                        wait_until_finzalize = False
                    elif order_state == 'processing':
                        print(f'certificate is being issued! send a finalization request.')
                        #print(poll_response.headers['Retry-After'])
                        time.sleep(1)
                        wait_until_finzalize = False
                    elif order_state == 'valid':
                        print(f'order is valid! ready to download certificate')
                        wait_until_finzalize = False
                    else:
                        print(f'order state unknown {order_state}')
                        return False
            else: 
                print(f'polling failed, status code {poll_response.status_code}. we wait and try again.')
                time.sleep(3)

        # ----------- 7.4 Finalize the order by submitting CSR -----------

        csr_der = self.create_CSR(identifiers)
        csr_payload = {
            "csr": self.enc_to_base64(csr_der)
        }
        finalize_json = self.jws_wrap(self.finalize_url, payload=csr_payload)
        finalize_response = self.session.post(self.finalize_url, verify=cert_bundle, json=finalize_json)

        if finalize_response.status_code != 200:
            print(f"Finalizing failed {finalize_response.json()}")
            return False
        
        # See 7.4, we have to check the state of the order before downloading the certificate
        # order has state: invalid, pending, ready, processing, valid where valid is equivalent to the certificate is ready to download
        while(True):
            poll_json = self.jws_wrap(self.order_url, payload="")
            poll_response = self.session.post(self.order_url, verify=cert_bundle, json=poll_json)

            #print(poll_response.json())
            if poll_response.status_code == 200:
                order_state = poll_response.json()["status"]
                if order_state == 'invalid':
                    print("Invalid, order process abandoned")
                    return False
                elif order_state == 'pending':
                    print("Pending state, client has not fullfilled the requirements")
                    return False
                elif order_state == 'ready':
                    print("Finalize request is ready.")
                    return False
                elif order_state == 'processing':
                    print(f'order still processing. we wait {3} sec until we poll again!')
                    print(poll_response.headers['Retry-After'])
                    time.sleep(3)
                elif order_state == 'valid':
                    print(f'order is valid! ready to download certificate')
                    self.certificate_download_url = poll_response.json()['certificate']
                    return True
                else:
                    print(f'order state unknown {order_state}')
                    time.sleep(1)
                    return False
            else: 
                print(f'polling failed, status code {poll_response.status_code}')

        #print(finalize_response.json())


    def download_certificate(self):
        download_certificate_json = self.jws_wrap(self.certificate_download_url, payload="")
        download_certificate_response = self.session.post(self.certificate_download_url, verify=cert_bundle, json=download_certificate_json)

        if download_certificate_response.status_code == 200:
            print('**Certificate downloaded!**')

        else: 
            print('Certificate download failed!')
            print(download_certificate_response.json())

        self.certificate_pem = download_certificate_response.content 
        return self.CSR_key, self.certificate_pem # PEM


    # 7.6. Certificate Revocation
    def revoke_certificate(self):

        cert_pem = x509.load_pem_x509_certificate(self.certificate_pem)

        cert_der = cert_pem.public_bytes(serialization.Encoding.DER)

        payload = {
            "certificate" : self.enc_to_base64(cert_der)
        }

        revoke_certificate_json = self.jws_wrap(self.revoke_cert_url, payload=payload)
        revoke_certificate_response = self.session.post(self.revoke_cert_url, verify=cert_bundle, json=revoke_certificate_json)

        if revoke_certificate_response.status_code == 200:
            print('**Certificate revoked!**')

            



            




