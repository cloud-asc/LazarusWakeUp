#!/usr/bin/env python3

from colorama import Fore, Style
from .ace_utils import ACEParser

class RelationshipMapper:
    def __init__(self, ldap_conn, logger):
        self.ldap_conn = ldap_conn
        self.logger = logger
        self.ace_parser = ACEParser(ldap_conn, logger)

    def analyze_inbound_relationships(self, target_dn):
        """Analyze what permissions other objects have over the target"""
        self.logger.info(f"Analyzing inbound relationships for: {target_dn}")
        
        # Get target object with security descriptor
        target = self.ldap_conn.get_object_by_dn(target_dn)
        if not target:
            self.logger.error("Target object not found")
            return None
        
        # Parse security descriptor
        sd_bytes = target.nTSecurityDescriptor.raw_values[0] if target.nTSecurityDescriptor else None
        if not sd_bytes:
            self.logger.warning("No security descriptor found")
            return None
        
        aces = self.ace_parser.parse_ntSecurityDescriptor(sd_bytes)
        
        # Filter interesting ACEs
        interesting_aces = []
        dangerous_rights = [
            'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner',
            'Self', 'WriteProperty', 'ExtendedRight'
        ]
        
        for ace in aces:
            if ace.get('type') in ['ACCESS_ALLOWED', 'ACCESS_ALLOWED_OBJECT']:
                # Check if ACE has dangerous rights
                rights = ace.get('rights', [])
                if any(right in dangerous_rights for right in rights):
                    # Don't include inherited ACEs or SYSTEM/Administrators
                    trustee = ace.get('trustee', '')
                    if not ace.get('inherited') and 'SYSTEM' not in trustee and 'Administrators' not in trustee:
                        interesting_aces.append(ace)
        
        return {
            'target_dn': target_dn,
            'target_sam': str(target.sAMAccountName) if target.sAMAccountName else 'N/A',
            'aces': interesting_aces
        }

    def display_inbound_relationships(self, analysis):
        """Display inbound relationship analysis"""
        if not analysis or not analysis.get('aces'):
            self.logger.warning("No interesting inbound relationships found")
            return
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Inbound Relationships for: {analysis['target_sam']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        print(f"Target DN: {analysis['target_dn']}\n")
        
        for i, ace in enumerate(analysis['aces'], 1):
            trustee = ace.get('trustee', 'Unknown')
            rights = ', '.join(ace.get('rights', []))
            ace_type = ace.get('type', 'Unknown')
            
            print(f"{Fore.YELLOW}[{i}] {trustee}{Style.RESET_ALL}")
            print(f"    Type: {ace_type}")
            print(f"    Rights: {Fore.RED}{rights}{Style.RESET_ALL}")
            
            if ace.get('object_type_name'):
                print(f"    Object Type: {ace['object_type_name']}")
            
            print()