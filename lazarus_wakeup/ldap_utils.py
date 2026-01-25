#!/usr/bin/env python3

import ldap3
from ldap3 import Server, Connection, ALL, NTLM, SASL, KERBEROS, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars
import ssl
import dns.resolver
from colorama import Fore, Style

class LDAPConnection:
    def __init__(self, args, logger):
        self.args = args
        self.logger = logger
        self.server_address = args.dc_ip if hasattr(args, 'dc_ip') else None
        self.domain = args.domain
        # Handle both 'user' and 'username' for compatibility
        self.username = args.user if hasattr(args, 'user') else args.username
        self.password = args.password if hasattr(args, 'password') else None
        self.nthash = args.nthash if hasattr(args, 'nthash') else None
        self.lmhash = args.lmhash if hasattr(args, 'lmhash') and args.lmhash else 'aad3b435b51404eeaad3b435b51404ee'
        self.use_kerberos = args.kerberos if hasattr(args, 'kerberos') else False
        self.use_ssl = args.ssl if hasattr(args, 'ssl') else False
        self.base_dn = self.domain_to_basedn(self.domain)
        self.conn = None
        self.port = args.port if hasattr(args, 'port') else None
        
        # Get DC if not specified
        if not self.server_address:
            self.server_address = self.get_dc_from_dns()

    def domain_to_basedn(self, domain):
        """Convert domain name to LDAP base DN"""
        parts = domain.split('.')
        return ','.join([f'DC={part}' for part in parts])

    def get_dc_from_dns(self):
        """Resolve DC from DNS SRV records"""
        try:
            srv_query = f"_ldap._tcp.dc._msdcs.{self.domain}"
            self.logger.debug(f"Resolving DC via DNS: {srv_query}")
            answers = dns.resolver.resolve(srv_query, 'SRV')
            dc = str(answers[0].target).rstrip('.')
            self.logger.success(f"Resolved DC: {dc}")
            return dc
        except Exception as e:
            self.logger.error(f"Failed to resolve DC via DNS: {e}")
            self.logger.error("Please specify DC IP with --dc-ip")
            return None

    def connect(self):
        """Establish LDAP connection"""
        try:
            if not self.server_address:
                return False

            port = self.port if self.port else (636 if self.use_ssl else 389)
            
            # TLS configuration
            tls = None
            if self.use_ssl:
                tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

            server = Server(
                self.server_address,
                port=port,
                use_ssl=self.use_ssl,
                tls=tls,
                get_info=ALL
            )

            # Authentication
            if self.use_kerberos:
                self.logger.info(f"Using Kerberos authentication as {self.username}@{self.domain}")
                self.conn = self._kerberos_auth(server)
            elif self.nthash:
                self.logger.info(f"Using NTLM authentication with hash for {self.username}")
                self.conn = self._ntlm_auth(server, use_hash=True)
            else:
                self.logger.info(f"Using password authentication for {self.username}")
                self.conn = self._simple_auth(server)

            if self.conn and self.conn.bind():
                self.logger.success(f"Successfully authenticated to {self.server_address}")
                self.logger.debug(f"Base DN: {self.base_dn}")
                return True
            else:
                self.logger.error("Authentication failed")
                if self.conn and self.conn.result:
                    self.logger.error(f"LDAP Error: {self.conn.result}")
                return False

        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            return False

    def _simple_auth(self, server):
        """Simple bind authentication"""
        user_dn = f"{self.username}@{self.domain}"
        return Connection(server, user=user_dn, password=self.password, auto_bind=False)

    def _ntlm_auth(self, server, use_hash=False):
        """NTLM authentication"""
        user = f"{self.domain}\\{self.username}"
        password = f"{self.lmhash}:{self.nthash}" if use_hash else self.password
        return Connection(server, user=user, password=password, authentication=NTLM, auto_bind=False)

    def _kerberos_auth(self, server):
        """Kerberos authentication"""
        try:
            user_principal = f"{self.username}@{self.domain.upper()}"
            return Connection(
                server, 
                user=user_principal, 
                password=self.password,
                authentication=SASL, 
                sasl_mechanism=KERBEROS, 
                auto_bind=False
            )
        except:
            self.logger.warning("Kerberos failed, falling back to NTLM")
            return self._ntlm_auth(server)

    def search(self, search_filter, attributes, search_base=None):
        """Perform LDAP search"""
        if not search_base:
            search_base = self.base_dn
        
        try:
            self.conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes
            )
            return self.conn.entries
        except Exception as e:
            self.logger.error(f"Search error: {e}")
            return []

    def search_with_sd(self, search_filter, attributes, search_base=None):
        """Search with security descriptor control"""
        if not search_base:
            search_base = self.base_dn
        
        try:
            controls = security_descriptor_control(sdflags=0x07)
            self.conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                controls=controls
            )
            return self.conn.entries
        except Exception as e:
            self.logger.error(f"Search with SD error: {e}")
            return []

    def modify(self, dn, changes):
        """Modify LDAP object"""
        try:
            result = self.conn.modify(dn, changes)
            if result:
                return True
            else:
                self.logger.error(f"Modify failed: {self.conn.result}")
                return False
        except Exception as e:
            self.logger.error(f"Modify error: {e}")
            return False

    def get_object_by_sam(self, sam_account_name):
        """Get object by sAMAccountName"""
        search_filter = f"(sAMAccountName={escape_filter_chars(sam_account_name)})"
        attributes = ['*', 'nTSecurityDescriptor']
        entries = self.search_with_sd(search_filter, attributes)
        return entries[0] if entries else None

    def get_object_by_dn(self, dn):
        """Get object by DN"""
        try:
            self.conn.search(
                search_base=dn,
                search_filter='(objectClass=*)',
                search_scope=ldap3.BASE,
                attributes=['*', 'nTSecurityDescriptor'],
                controls=security_descriptor_control(sdflags=0x07)
            )
            return self.conn.entries[0] if self.conn.entries else None
        except Exception as e:
            self.logger.error(f"Failed to get object {dn}: {e}")
            return None

    def unbind(self):
        """Close connection"""
        if self.conn:
            self.conn.unbind()