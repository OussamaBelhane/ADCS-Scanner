from ldap3 import Server, Connection, NTLM

ip = "192.168.181.129"
domain_user = "invictus.local\\john"
password = "Password123!"

server = Server(ip)
conn = Connection(server,user=domain_user,password=password,authentication=NTLM)

if conn.bind():
    print("[+] SUCCESS: We are connected to the Domain Controller!")
else:
    print("[-] FAILED: Could not log in.")
    