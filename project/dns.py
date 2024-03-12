# inspired by: https://stackoverflow.com/questions/33531551/how-to-create-a-very-simple-dns-server-using-python

from dnslib import RR, QTYPE, TXT, A
from dnslib.server import DNSServer

PORT =  10053 # DNS server: has to run on UDP port 10053 according to project description

# similar to https://github.com/paulc/dnslib/blob/master/dnslib/zoneresolver.py
class SimpleResolver(object):
    def __init__(self):
        self.zone = [] # keep a list of ressource rescords we want to add to the response in resolve().

    def resolve(self, request, handler):
        reply = request.reply()

        for rr in self.zone:
            reply.add_answer(rr)

        return reply

    # add RR (ressource record) to zone
    # example: rr=RR("william.com", QTYPE.A, rdata -> TXT(..), ttl -> time to live in secods)
    def zone_add_record(self, rr):
        #print(f' ADDING RECORD {rr}' )
        self.zone.append(rr)
        
# using DNSServer from https://github.com/paulc/dnslib/blob/master/dnslib/server.py
# and our custom Resolver
class SimpleDNSServer(object):
    def __init__(self):
        self.resolver = SimpleResolver()
        self.dns_server = DNSServer(self.resolver, port=PORT)

    def add_txt_record(self, domain, rdata, ttl=400):
        self.resolver.zone_add_record(RR(domain, QTYPE.TXT, rdata=TXT(rdata), ttl=ttl))

    def add_address_record(self, domain, ip_addr, ttl=400):
        self.resolver.zone_add_record(RR(domain, QTYPE.A, rdata=A(ip_addr), ttl=ttl))

    def start_server(self):
        print('starting DNS server on Port: ' +str(PORT))
        self.dns_server.start_thread()

    def stop_server(self):
        self.dns_server.stop()

    def is_alive(self):
        return self.dns_server.isAlive()

''' example: 

if __name__ == '__main__':
    simplDnsServer = SimpleDNSServer()
    simplDnsServer.add_txt_record("william.com", "hallo hihi hehe")

    simplDnsServer.start_server()

    print("started!")

    simplDnsServer.stop_server()

    print("stopped")

'''