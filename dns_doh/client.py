import random
import requests
import struct
import sys

from base64 import urlsafe_b64encode

#    The DNS HEADER
#    Reference: https://www.rfc-editor.org/rfc/rfc1035
# 
#     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      ID                       |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                    QDCOUNT                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                    ANCOUNT                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                    NSCOUNT                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                    ARCOUNT                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

OPENDNS_URL = 'https://doh.opendns.com'

def labeled_domain(domain: str):
    """ Construct a labled domain byte-sequence as per section 4.1.2 in RFC1035.

        This means each part of the FQDN will have it's length prepended to the part.
        www.cstromblad.com would become: 3www10cstromblad3com (but in hex)."""

    ds = domain.split(".")

    domain_construct = b""
    for part in ds:
        domain_construct += struct.pack(f">B{len(part)}s", len(part), part.encode())

    return domain_construct + struct.pack(">B", 0x0) # Zero length octet for the null label of the root

def construct_query(domain: str):
    """ Build and return very simple DNS-query packet in wire-format for <domain>. 

        This is not a useful function, it's for educational purposes only."""

    flags = 0x100 # RD-bit set

    id_ = random.randint(1, 65535)
    qdcount = 0x1 
    ancount = 0x0
    nscount = 0x0
    arcount = 0x0

    preamble = struct.pack(">HHHHHH", id_, flags, qdcount, ancount, nscount, arcount)
    ld = labeled_domain(domain)
    postamble = struct.pack(">HH", 0x1, 0x1)

    return preamble + ld + postamble

def do_main(domain: str):

    q = construct_query(domain)

    for c in q:
        print(f'{c:02x} ', end = '')

    doh_request = urlsafe_b64encode(q).rstrip(b'=')
    print(doh_request)

    # Send DNS-request to DoH-enabled server.
    headers= {'Content-type': 'application/dns-message'}
    response = requests.get(f"{OPENDNS_URL}/dns-query?dns={doh_request.decode()}", headers=headers)

    print(response.content)

if __name__ == "__main__":

    do_main(sys.argv[1])
