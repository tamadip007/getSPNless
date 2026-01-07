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
#   This script is a collection of functions to change or reset the password of
#   a user via various protocols.
#
#   Examples:
#     SAMR protocol over SMB transport to change passwords (like smbpasswd, -protocol smb-samr is implied)
#       changepasswd.py j.doe@192.168.1.11
#       changepasswd.py contoso.local/j.doe@DC1 -hashes :fc525c9683e8fe067095ba2ddc971889
#       changepasswd.py -protocol smb-samr contoso.local/j.doe:'Passw0rd!'@DC1 -newpass 'N3wPassw0rd!'
#       changepasswd.py contoso.local/j.doe:'Passw0rd!'@DC1 -newhashes :126502da14a98b58f2c319b81b3a49cb
#       changepasswd.py contoso.local/j.doe@DC1 -newhashes :126502da14a98b58f2c319b81b3a49cb -k -no-pass
#
# This script is based on smbpasswd.py.
#
# Authors:
#   @snovvcrash
#   @alef-burzmali
#   @bransh
#   @Oddvarmoe
#   @p0dalirius

import logging
from impacket.dcerpc.v5 import transport, samr

class PasswordHandler:
    """Generic interface for using SMB/SAMR for password protocols supported by this script"""

    def __init__(
        self,
        address,
        domain="",
        authUsername="",
        authPassword="",
        authPwdHashLM="",
        authPwdHashNT="",
        doKerberos=False,
        aesKey="",
        kdcHost=None,
    ):
        """
        Instantiate password change or reset with the credentials of the account making the changes.
        It can be the target user, or a privileged account.

        :param string address:  IP address or hostname of the server or domain controller where the password will be changed
        :param string domain:   AD domain where the password will be changed
        :param string username: account that will attempt the password change or reset on the target(s)
        :param string password: password of the account that will attempt the password change
        :param string pwdHashLM: LM hash of the account that will attempt the password change
        :param string pwdHashNT: NT hash of the account that will attempt the password change
        :param bool doKerberos: use Kerberos authentication instead of NTLM
        :param string aesKey:   AES key for Kerberos authentication
        :param string kdcHost:  KDC host
        """

        self.address = address
        self.domain = domain
        self.username = authUsername
        self.password = authPassword
        self.pwdHashLM = authPwdHashLM
        self.pwdHashNT = authPwdHashNT
        self.doKerberos = doKerberos
        self.aesKey = aesKey
        self.kdcHost = kdcHost

    def _changePassword(
        self, targetUsername, targetDomain, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
    ):
        """Implementation of a password change"""
        raise NotImplementedError

    def changePassword(
        self,
        targetUsername=None,
        targetDomain=None,
        oldPassword=None,
        newPassword="",
        oldPwdHashLM=None,
        oldPwdHashNT=None,
        newPwdHashLM="",
        newPwdHashNT="",
    ):
        """
        Change the password of a target account, knowing the previous password.

        :param string targetUsername: account whose password will be changed, if different from the user performing the change
        :param string targetDomain:   domain of the account
        :param string oldPassword:    current password
        :param string newPassword:    new password
        :param string oldPwdHashLM:   current password, as LM hash
        :param string oldPwdHashMT:   current password, as NT hash
        :param string newPwdHashLM:   new password, as LM hash
        :param string newPwdHashMT:   new password, as NT hash

        :return bool success
        """

        if targetUsername is None:
            # changing self
            targetUsername = self.username

            if targetDomain is None:
                targetDomain = self.domain
            if oldPassword is None:
                oldPassword = self.password
            if oldPwdHashLM is None:
                oldPwdHashLM = self.pwdHashLM
            if oldPwdHashNT is None:
                oldPwdHashNT = self.pwdHashNT

        logging.info(f"Changing the password of {targetDomain}\\{targetUsername}")
        return self._changePassword(
            targetUsername, targetDomain, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
        )

    def _setPassword(self, targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT):
        """Implementation of a password set"""
        raise NotImplementedError

    def setPassword(self, targetUsername, targetDomain=None, newPassword="", newPwdHashLM="", newPwdHashNT=""):
        """
        Set or Reset the password of a target account, with privileges.

        :param string targetUsername:   account whose password will be changed
        :param string targetDomain:     domain of the account
        :param string newPassword:      new password
        :param string newPwdHashLM:     new password, as LM hash
        :param string newPwdHashMT:     new password, as NT hash

        :return bool success
        """

        if targetDomain is None:
            targetDomain = self.domain

        logging.info(f"Setting the password of {targetDomain}\\{targetUsername} as {self.domain}\\{self.username}")
        return self._setPassword(targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT)

class SamrPassword(PasswordHandler):
    """Use MS-SAMR protocol to change or reset the password of a user"""

    # our binding with SAMR
    dce = None
    anonymous = False

    def rpctransport(self):
        """
        Return a new transport for our RPC/DCE.

        :return rpc: RPC transport instance
        """
        raise NotImplementedError

    def authenticate(self, anonymous=False):
        """
        Instantiate a new transport and try to authenticate

        :param bool anonymous: Attempt a null binding
        :return dce: DCE/RPC, bound to SAMR
        """

        rpctransport = self.rpctransport()

        if hasattr(rpctransport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            if anonymous:
                rpctransport.set_credentials(username="", password="", domain="", lmhash="", nthash="", aesKey="")
            else:
                rpctransport.set_credentials(
                    self.username,
                    self.password,
                    self.domain,
                    self.pwdHashLM,
                    self.pwdHashNT,
                    aesKey=self.aesKey,
                )

        if anonymous:
            self.anonymous = True
            rpctransport.set_kerberos(False, None)
        else:
            self.anonymous = False
            rpctransport.set_kerberos(self.doKerberos, self.kdcHost)

        as_user = "null session" if anonymous else f"{self.domain}\\{self.username}"
        logging.info(f"Connecting to DCE/RPC as {as_user}")

        dce = rpctransport.get_dce_rpc()
        dce.connect()

        dce.bind(samr.MSRPC_UUID_SAMR)
        logging.debug("Successfully bound to SAMR")
        return dce

    def connect(self, retry_if_expired=False):
        """
        Connect to SAMR using our transport protocol.

        This method must instantiate self.dce

        :param bool retry_if_expired: Retry as null binding if our password is expired
        :return bool: success
        """

        if self.dce:
            # Already connected
            return True

        try:
            self.dce = self.authenticate(anonymous=False)

        except Exception as e:
            if any(msg in str(e) for msg in ("STATUS_PASSWORD_MUST_CHANGE", "STATUS_PASSWORD_EXPIRED")):
                if retry_if_expired:
                    logging.warning("Password is expired or must be changed, trying to bind with a null session.")
                    self.dce = self.authenticate(anonymous=True)
                else:
                    logging.critical(
                        "Cannot set new NTLM hashes when current password is expired. Provide a plaintext value for the "
                        "new password."
                    )
                    logging.debug(str(e))
                    return False
            elif "STATUS_LOGON_FAILURE" in str(e):
                logging.critical("Authentication failure when connecting to RPC: wrong credentials?")
                logging.debug(str(e))
                return False
            elif "STATUS_ACCOUNT_RESTRICTION" in str(e):
                logging.critical(
                    "Account restriction: username and credentials are valid, but some other restriction prevents"
                    "authentication, like 'Protected Users' group or time-of-day restriction"
                )
                logging.debug(str(e))
                return False
            elif "STATUS_ACCOUNT_DISABLED" in str(e):
                logging.critical("The account is currently disabled.")
                logging.debug(str(e))
                return False
            else:
                raise e

        return True

    def hSamrOpenUser(self, username):
        """Open an handle on the target user"""
        try:
            serverHandle = samr.hSamrConnect(self.dce, self.address + "\x00")["ServerHandle"]
            domainSID = samr.hSamrLookupDomainInSamServer(self.dce, serverHandle, self.domain)["DomainId"]
            domainHandle = samr.hSamrOpenDomain(self.dce, serverHandle, domainId=domainSID)["DomainHandle"]
            userRID = samr.hSamrLookupNamesInDomain(self.dce, domainHandle, (username,))["RelativeIds"]["Element"][0]
            userHandle = samr.hSamrOpenUser(self.dce, domainHandle, userId=userRID)["UserHandle"]
        except Exception as e:
            if "STATUS_NO_SUCH_DOMAIN" in str(e):
                logging.critical(
                    "Wrong realm. Try to set the domain name for the target user account explicitly in format "
                    "DOMAIN/username."
                )
                logging.debug(str(e))
                return False
            elif self.anonymous and "STATUS_ACCESS_DENIED" in str(e):
                logging.critical(
                    "Our anonymous session cannot get a handle to the target user. "
                    "Retry with a user whose password is not expired."
                )
                logging.debug(str(e))
                return False
            elif "STATUS_ACCESS_DENIED" in str(e):
                logging.critical("Access denied")
                logging.debug(str(e))
                return False
            else:
                raise e

        return userHandle

    def _SamrWrapper(self, samrProcedure, *args, _change=True, **kwargs):
        """
        Handles common errors when changing/resetting the password, regardless of the procedure

        :param callable samrProcedure: Function that will send the SAMR call
                                args and kwargs are passed verbatim
        :param bool _change:    Used for more precise error reporting,
                                True if it is a password change, False if it is a reset
        """
        logging.debug(f"Sending SAMR call {samrProcedure.__name__}")
        try:
            resp = samrProcedure(self.dce, *args, **kwargs)
        except Exception as e:
            if "STATUS_PASSWORD_RESTRICTION" in str(e):
                logging.critical(
                    "Some password update rule has been violated. For example, the password history policy may prohibit the "
                    "use of recent passwords or the password may not meet length criteria."
                )
                logging.debug(str(e))
                return False
            elif "STATUS_ACCESS_DENIED" in str(e):
                if _change:
                    logging.critical("Target user is not allowed to change their own password")
                else:
                    logging.critical(f"{self.domain}\\{self.username} user is not allowed to set the password of the target")
                logging.debug(str(e))
                return False
            else:
                raise e

        if resp["ErrorCode"] == 0:
            logging.info("Password was changed successfully.")
            return True

        logging.error("Non-zero return code, something weird happened.")
        resp.dump()
        return False

    def hSamrUnicodeChangePasswordUser2(
        self, username, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
    ):
        return self._SamrWrapper(
            samr.hSamrUnicodeChangePasswordUser2,
            "\x00",
            username,
            oldPassword,
            newPassword,
            oldPwdHashLM,
            oldPwdHashNT,
            _change=True,
        )

    def hSamrChangePasswordUser(
        self, username, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
    ):
        userHandle = self.hSamrOpenUser(username)
        if not userHandle:
            return False

        return self._SamrWrapper(
            samr.hSamrChangePasswordUser,
            userHandle,
            oldPassword=oldPassword,
            newPassword=newPassword,
            oldPwdHashNT=oldPwdHashNT,
            newPwdHashLM=newPwdHashLM,
            newPwdHashNT=newPwdHashNT,
            _change=True,
        )

    def hSamrSetInformationUser(self, username, newPassword, newPwdHashLM, newPwdHashNT):
        userHandle = self.hSamrOpenUser(username)
        if not userHandle:
            return False

        return self._SamrWrapper(samr.hSamrSetNTInternal1, userHandle, newPassword, newPwdHashNT, _change=False)

    def _changePassword(
        self, targetUsername, targetDomain, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
    ):
        if not self.connect(retry_if_expired=True):
            return False

        if newPassword:
            # If using a plaintext value for the new password
            return self.hSamrUnicodeChangePasswordUser2(
                targetUsername, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT, "", ""
            )
        else:
            # If using NTLM hashes for the new password
            res = self.hSamrChangePasswordUser(
                targetUsername, oldPassword, "", oldPwdHashLM, oldPwdHashNT, newPwdHashLM, newPwdHashNT
            )
            if res:
                logging.warning("User might need to change their password at next logon because we set hashes (unless password never expires is set).")
            return res

    def _setPassword(self, targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT):
        if not self.connect(retry_if_expired=False):
            return False

        # If resetting the password with admin privileges
        res = self.hSamrSetInformationUser(targetUsername, newPassword, newPwdHashLM, newPwdHashNT)
        if res:
            logging.warning("User no longer has valid AES keys for Kerberos, until they change their password again.")
        return res

class SmbPassword(SamrPassword):
    def rpctransport(self):
        return transport.SMBTransport(self.address, filename=r"\samr")