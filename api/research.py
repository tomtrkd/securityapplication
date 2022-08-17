from calendar import c
from tinydb import TinyDB, Query
from tinydb.operations import set as sets

import csv
import pickle

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna

from socket import socket
from collections import namedtuple
import signal
from contextlib import contextmanager

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')

def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()
    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE
    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)
   
DV = "2.23.140.1.2.1"
OV = "2.23.140.1.2.2"
EV = "2.23.140.1.1"

db = TinyDB('tls_db.json')
search = Query()

with open('top-1m.csv') as f:
    print(type(f))
    reader = csv.reader(f)
    print(type(reader))
    data = list(reader)
    print(type(data))

top1m = []

for line in data:
    entry = {"rank": int(line[0]), "domain": line[1]}
    top1m.append(entry)
processed = db.all()
found = set()
for x in processed:
    found.add(x["rank"])

count = 0 
blob = []
while count <= 99999:
    rank = count + 1
    if count % 1000 == 0:
        print(rank)
        db.insert_multiple(blob)
        blob = []

    if rank in found:
        count = count + 1
        continue
    else:       
        domain = top1m[count]["domain"] 

        try:
            test_data = get_certificate(domain, 443)

            try:
                cert_pol = test_data.cert.extensions.get_extension_for_class(x509.CertificatePolicies)
                cert_pol = str(cert_pol)

                if DV in cert_pol:
                    cert_type = "dv"

                elif EV in cert_pol:
                    cert_type = "ev"

                elif OV in cert_pol:
                    cert_type = "ov"

                else:
                    cert_type = "not_found"

                pending = top1m[count]
                pending["cert_type"] = cert_type
                blob.append(pending)
                count = count + 1

            except:
                pending = top1m[count]
                cert_type = "not_found"
                pending["cert_type"] = cert_type
                blob.append(pending)
                count = count + 1

        except:
            pending = top1m[count]
            cert_type = "denied"
            pending["cert_type"] = cert_type
            blob.append(pending)
            count = count + 1






   