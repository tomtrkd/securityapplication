import pickle

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna

from socket import socket
from collections import namedtuple

file_in = open("top1m.pickle","rb")
top1m = pickle.load(file_in)

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


for domain in top1m:
    print(str(count)+ " of " + str(len(top1m)))

    print(domain)
    try:
        test_data = get_certificate(domain, 443)

        try:
            cert_pol = test_data.cert.extensions.get_extension_for_class(x509.CertificatePolicies)
            cert_pol = str(cert_pol)

            if DV in cert_pol:
                print("DV Cert")
                DV_Count = DV_Count + 1

            elif EV in cert_pol:
                print("EV Cert")
                EV_Count = EV_Count + 1

            elif OV in cert_pol:
                print("OV Cert")
                OV_Count = OV_Count + 1

            else:
                print("No CertificatePolicies Found")
                notfound = notfound + 1
        except:
            print("No CertificatePolicies Found")
            notfound = notfound + 1
    except:
        print("can not connect")
        no_connection = no_connection + 1

    count = count +1
    print("\n")

print("Number could not connnect to: " + str(no_connection))
print("Number not found: " + str(notfound))
print("Number of DV: " + str(DV_Count))
print("Number of EV: " + str(EV_Count))
print("Number of OV: " + str(OV_Count)) 


    