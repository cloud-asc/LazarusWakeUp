#!/usr/bin/env python3

import argparse
import sys
import os
from colorama import Fore, Style, init
from ldap3 import MODIFY_REPLACE
from .ldap_utils import LDAPConnection
from .relationship_mapper import RelationshipMapper

# Initialize colorama
init(autoreset=True)

class Logger:
    def __init__(self, verbose=0):
        self.verbosity = verbose  # Changed from self.verbose to self.verbosity

    def info(self, msg):
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")

    def success(self, msg):
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

    def error(self, msg):
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

    def warning(self, msg):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

    def debug(self, msg):
        if self.verbosity >= 2:  # Changed from self.verbose to self.verbosity
            print(f"{Fore.MAGENTA}[D]{Style.RESET_ALL} {msg}")
    
    def verbose(self, msg):
        if self.verbosity >= 1:  # Changed from self.verbose to self.verbosity
            print(f"{Fore.BLUE}[V]{Style.RESET_ALL} {msg}")

class LazarusWakeUp:
    def __init__(self, args):
        self.args = args
        self.logger = Logger(args.verbose)
        self.ldap = LDAPConnection(args, self.logger)
        self.mapper = None
        # Accounts to exclude from results
        self.excluded_accounts = ['guest', 'krbtgt']

    def run(self):
        """Main execution flow"""
        if not self.ldap.connect():
            return False
        
        self.mapper = RelationshipMapper(self.ldap, self.logger)
        
        # Mode selection
        if self.args.action == 'find':
            self.find_disabled_objects()
        elif self.args.action == 'find-all':
            self.find_all_disabled_objects()
        elif self.args.action == 'enable':
            self.enable_objects()
        elif self.args.action == 'disable':
            self.disable_objects()
        
        self.ldap.unbind()
        return True

    def is_excluded_account(self, sam_account_name):
        """Check if account should be excluded from results"""
        if not sam_account_name:
            return False
        return sam_account_name.lower() in self.excluded_accounts

    def get_targets(self):
        """Get list of targets from command line or file"""
        targets = []
        
        # Single target
        if self.args.target:
            targets.append(self.args.target)
        
        # Target list file
        if self.args.target_list:
            if not os.path.exists(self.args.target_list):
                self.logger.error(f"Target list file not found: {self.args.target_list}")
                return []
            
            try:
                with open(self.args.target_list, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            targets.append(line)
                self.logger.info(f"Loaded {len(targets)} targets from file")
            except Exception as e:
                self.logger.error(f"Failed to read target list: {e}")
                return []
        
        return targets

    def find_disabled_objects(self):
        """Find specific disabled objects and analyze their relationships"""
        targets = self.get_targets()
        
        if not targets:
            self.logger.error("No targets specified. Use -t for single target or -tl for target list")
            return
        
        self.logger.info(f"Searching for {len(targets)} specific disabled AD object(s)...")
        
        found_entries = []
        
        for target in targets:
            self.logger.verbose(f"Searching for: {target}")
            
            # Build filter for specific target
            ldap_filter = f"(&(userAccountControl:1.2.840.113556.1.4.803:=2)(|(objectClass=user)(objectClass=computer))(sAMAccountName={target}))"
            
            attributes = [
                'distinguishedName', 'cn', 'sAMAccountName', 'objectClass',
                'description', 'userAccountControl', 'whenCreated', 'whenChanged',
                'memberOf', 'pwdLastSet', 'lastLogon', 'servicePrincipalName'
            ]
            
            entries = self.ldap.search(ldap_filter, attributes)
            
            if entries:
                sam = str(entries[0].sAMAccountName) if entries[0].sAMAccountName else None
                if not self.is_excluded_account(sam):
                    found_entries.append(entries[0])
                    self.logger.debug(f"Found: {target}")
                else:
                    self.logger.warning(f"Skipped excluded account: {target}")
            else:
                self.logger.warning(f"Not found or not disabled: {target}")
        
        if not found_entries:
            self.logger.warning("No disabled objects found")
            return
        
        self.logger.success(f"Found {len(found_entries)} disabled object(s)")
        
        # Display results with relationship analysis
        self.display_and_analyze_objects(found_entries)

    def find_all_disabled_objects(self):
        """Find all disabled objects including groups, OUs, etc. and analyze their relationships"""
        self.logger.info("Searching for all types of disabled AD objects...")
        
        # Search for all object types that can be disabled
        ldap_filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=2)(!(sAMAccountName=Guest))(!(sAMAccountName=krbtgt)))"
        
        attributes = [
            'distinguishedName', 'cn', 'sAMAccountName', 'objectClass',
            'description', 'userAccountControl', 'whenCreated', 'whenChanged',
            'memberOf', 'pwdLastSet', 'lastLogon', 'servicePrincipalName'
        ]
        
        entries = self.ldap.search(ldap_filter, attributes)
        
        # Additional client-side filtering (case-insensitive)
        filtered_entries = []
        for entry in entries:
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else None
            if not self.is_excluded_account(sam):
                filtered_entries.append(entry)
            else:
                self.logger.debug(f"Excluded account: {sam}")
        
        if not filtered_entries:
            self.logger.warning("No disabled objects found (excluding Guest and krbtgt)")
            return
        
        self.logger.success(f"Found {len(filtered_entries)} disabled objects (excluding Guest and krbtgt)")
        
        # Display results with relationship analysis
        self.display_and_analyze_objects(filtered_entries)

    def display_and_analyze_objects(self, entries):
        """Display disabled objects and analyze their inbound relationships"""
        print(f"\n{Fore.CYAN}{'='*100}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Disabled AD Objects{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*100}{Style.RESET_ALL}\n")
        
        for i, entry in enumerate(entries, 1):
            sam = str(entry.sAMAccountName) if entry.sAMAccountName else 'N/A'
            cn = str(entry.cn) if entry.cn else 'N/A'
            dn = str(entry.distinguishedName)
            obj_class = self.get_primary_class(entry.objectClass)
            desc = str(entry.description) if entry.description else 'N/A'
            created = str(entry.whenCreated) if entry.whenCreated else 'N/A'
            modified = str(entry.whenChanged) if entry.whenChanged else 'N/A'
            
            # Check for SPNs (service accounts)
            spns = entry.servicePrincipalName.values if entry.servicePrincipalName else []
            is_service = "Yes" if spns else "No"
            
            # Properly extract userAccountControl
            try:
                if hasattr(entry.userAccountControl, 'value'):
                    uac = int(entry.userAccountControl.value)
                elif hasattr(entry.userAccountControl, 'values'):
                    uac = int(entry.userAccountControl.values[0])
                else:
                    uac = int(entry.userAccountControl)
                uac_display = f"{uac} (0x{uac:08x})"
            except:
                uac_display = "N/A"
            
            print(f"{Fore.YELLOW}[{i}] {obj_class.upper()}: {sam}{Style.RESET_ALL}")
            print(f"    DN:          {dn}")
            print(f"    CN:          {cn}")
            print(f"    Description: {desc}")
            print(f"    UAC:         {uac_display}")
            print(f"    Created:     {created}")
            print(f"    Modified:    {modified}")
            print(f"    Service Acc: {is_service}")
            if spns:
                print(f"    SPNs:        {', '.join([str(s) for s in spns[:3]])}")
            
            # Analyze inbound relationships for this object
            try:
                self.logger.verbose(f"\n    Analyzing inbound relationships for {sam}...")
                analysis = self.mapper.analyze_inbound_relationships(dn)
                
                if analysis and isinstance(analysis, dict) and analysis.get('aces'):
                    aces = analysis.get('aces')
                    if isinstance(aces, list) and len(aces) > 0:
                        print(f"\n    {Fore.CYAN}>>> Inbound Relationships:{Style.RESET_ALL}")
                        for j, ace in enumerate(aces, 1):
                            if not isinstance(ace, dict):
                                self.logger.debug(f"Skipping invalid ACE: {ace}")
                                continue
                                
                            trustee = ace.get('trustee', 'Unknown')
                            rights = ace.get('rights', [])
                            if isinstance(rights, list):
                                rights_str = ', '.join(rights)
                            else:
                                rights_str = str(rights)
                            ace_type = ace.get('type', 'Unknown')
                            
                            print(f"        [{j}] {Fore.YELLOW}{trustee}{Style.RESET_ALL}")
                            print(f"            Type: {ace_type}")
                            print(f"            Rights: {Fore.RED}{rights_str}{Style.RESET_ALL}")
                            
                            if ace.get('object_type_name'):
                                print(f"            Object Type: {ace['object_type_name']}")
                    else:
                        print(f"    {Fore.GREEN}>>> No interesting inbound relationships found{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.GREEN}>>> No interesting inbound relationships found{Style.RESET_ALL}")
            except Exception as e:
                self.logger.error(f"Error analyzing relationships for {sam}: {e}")
                if self.args.verbose >= 2:
                    import traceback
                    traceback.print_exc()
            
            print()

    def get_primary_class(self, object_classes):
        """Get primary object class"""
        if not object_classes:
            return 'unknown'
        
        priority = ['user', 'computer', 'group', 'organizationalUnit', 'contact']
        classes = [str(c).lower() for c in object_classes]
        
        for p in priority:
            if p in classes:
                return p
        
        return str(object_classes[-1]) if object_classes else 'unknown'

    def enable_objects(self):
        """Enable disabled object(s)"""
        targets = self.get_targets()
        
        if not targets:
            self.logger.error("No targets specified. Use -t for single target or -tl for target list")
            return
        
        self.logger.info(f"Processing {len(targets)} target(s) for enablement")
        
        success_count = 0
        fail_count = 0
        
        for target in targets:
            self.logger.verbose(f"\nProcessing: {target}")
            
            # Check if trying to enable excluded accounts
            if self.is_excluded_account(target):
                self.logger.error(f"Cannot enable protected account: {target}")
                self.logger.warning("Guest and krbtgt accounts are excluded from modification")
                fail_count += 1
                continue
            
            # Get object
            obj = self.ldap.get_object_by_sam(target)
            if not obj:
                self.logger.error(f"Object not found: {target}")
                fail_count += 1
                continue
            
            dn = str(obj.distinguishedName)
            
            # Properly extract userAccountControl value
            try:
                if hasattr(obj.userAccountControl, 'value'):
                    current_uac = int(obj.userAccountControl.value)
                elif hasattr(obj.userAccountControl, 'values'):
                    current_uac = int(obj.userAccountControl.values[0])
                else:
                    current_uac = int(obj.userAccountControl)
            except (TypeError, ValueError, AttributeError) as e:
                self.logger.error(f"Failed to read userAccountControl for {target}: {e}")
                fail_count += 1
                continue
            
            # Check if already enabled
            if not (current_uac & 0x0002):
                self.logger.warning(f"{target} is already enabled")
                continue
            
            # Show current state
            self.logger.debug(f"Current UAC for {target}: {current_uac} (0x{current_uac:08x})")
            
            # Calculate new UAC (remove ACCOUNTDISABLE bit)
            new_uac = current_uac & ~0x0002
            self.logger.debug(f"New UAC for {target}: {new_uac} (0x{new_uac:08x})")
            
            # Confirm if not forcing
            if not self.args.force and len(targets) == 1:
                response = input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Enable {target}? (Yes/no) [Yes]: ").strip()
                # Default to 'yes' if empty (just pressed Enter)
                if response == '':
                    response = 'yes'
                if response.lower() not in ['yes', 'y']:
                    self.logger.warning("Operation cancelled")
                    continue
            
            # Modify object
            changes = {
                'userAccountControl': [(MODIFY_REPLACE, [new_uac])]
            }
            
            if self.ldap.modify(dn, changes):
                self.logger.success(f"Successfully enabled: {target}")
                success_count += 1
            else:
                self.logger.error(f"Failed to enable: {target}")
                fail_count += 1
        
        # Summary
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Summary:{Style.RESET_ALL}")
        print(f"    Total targets:        {len(targets)}")
        print(f"    Successfully enabled: {success_count}")
        print(f"    Failed:               {fail_count}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

    def disable_objects(self):
        """Disable enabled object(s)"""
        targets = self.get_targets()
        
        if not targets:
            self.logger.error("No targets specified. Use -t for single target or -tl for target list")
            return
        
        self.logger.info(f"Processing {len(targets)} target(s) for disablement")
        
        success_count = 0
        fail_count = 0
        
        for target in targets:
            self.logger.verbose(f"\nProcessing: {target}")
            
            # Check if trying to disable excluded accounts
            if self.is_excluded_account(target):
                self.logger.error(f"Cannot disable protected account: {target}")
                self.logger.warning("Guest and krbtgt accounts are excluded from modification")
                fail_count += 1
                continue
            
            # Get object
            obj = self.ldap.get_object_by_sam(target)
            if not obj:
                self.logger.error(f"Object not found: {target}")
                fail_count += 1
                continue
            
            dn = str(obj.distinguishedName)
            
            # Properly extract userAccountControl value
            try:
                if hasattr(obj.userAccountControl, 'value'):
                    current_uac = int(obj.userAccountControl.value)
                elif hasattr(obj.userAccountControl, 'values'):
                    current_uac = int(obj.userAccountControl.values[0])
                else:
                    current_uac = int(obj.userAccountControl)
            except (TypeError, ValueError, AttributeError) as e:
                self.logger.error(f"Failed to read userAccountControl for {target}: {e}")
                fail_count += 1
                continue
            
            # Check if already disabled
            if current_uac & 0x0002:
                self.logger.warning(f"{target} is already disabled")
                continue
            
            # Show current state
            self.logger.debug(f"Current UAC for {target}: {current_uac} (0x{current_uac:08x})")
            
            # Calculate new UAC (add ACCOUNTDISABLE bit)
            new_uac = current_uac | 0x0002
            self.logger.debug(f"New UAC for {target}: {new_uac} (0x{new_uac:08x})")
            
            # Confirm if not forcing
            if not self.args.force and len(targets) == 1:
                response = input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Disable {target}? (Yes/no) [Yes]: ").strip()
                # Default to 'yes' if empty (just pressed Enter)
                if response == '':
                    response = 'yes'
                if response.lower() not in ['yes', 'y']:
                    self.logger.warning("Operation cancelled")
                    continue
            
            # Modify object
            changes = {
                'userAccountControl': [(MODIFY_REPLACE, [new_uac])]
            }
            
            if self.ldap.modify(dn, changes):
                self.logger.success(f"Successfully disabled: {target}")
                success_count += 1
            else:
                self.logger.error(f"Failed to disable: {target}")
                fail_count += 1
        
        # Summary
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Summary:{Style.RESET_ALL}")
        print(f"    Total targets:         {len(targets)}")
        print(f"    Successfully disabled: {success_count}")
        print(f"    Failed:                {fail_count}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

def print_banner():
    """Print tool banner"""
    banner = f"""{Fore.GREEN}
██╗      █████╗ ███████╗ █████╗ ██████╗ ██╗   ██╗███████╗    ██╗    ██╗ █████╗ ██╗  ██╗███████╗██╗   ██╗██████╗ 
██║     ██╔══██╗╚══███╔╝██╔══██╗██╔══██╗██║   ██║██╔════╝    ██║    ██║██╔══██╗██║ ██╔╝██╔════╝██║   ██║██╔══██╗
██║     ███████║  ███╔╝ ███████║██████╔╝██║   ██║███████╗    ██║ █╗ ██║███████║█████╔╝ █████╗  ██║   ██║██████╔╝
██║     ██╔══██║ ███╔╝  ██╔══██║██╔══██╗██║   ██║╚════██║    ██║███╗██║██╔══██║██╔═██╗ ██╔══╝  ██║   ██║██╔═══╝ 
███████╗██║  ██║███████╗██║  ██║██║  ██║╚██████╔╝███████║    ╚███╔███╔╝██║  ██║██║  ██╗███████╗╚██████╔╝██║     
╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝     ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝     
                                                                                                                
{Style.RESET_ALL}
              A Python-Based Tool for Reconnaissance and State Management of AD Principals v1.0.0
{Fore.CYAN}{'='*80}{Style.RESET_ALL}
    """
    print(banner)

def main():
    parser = argparse.ArgumentParser(
        description='LazarusWakeUp - Find, enable/disable, and analyze disabled AD principals',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Find all disabled users and computers (with relationship analysis)
  lazarus-wakeup -d CORP.LOCAL -u administrator -p Password123 -a find-all

  # Find specific disabled user
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 -a find -t jdoe

  # Find multiple specific disabled users from file
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 -a find -tl disabled_users.txt

  # Enable a disabled user
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 -a enable -t jdoe

  # Enable multiple users from file
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 -a enable -tl targets.txt --force

  # Disable a user
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 -a disable -t jdoe

  # Use NTLM hash
  lazarus-wakeup -d CORP.LOCAL -u admin -H :a87f3a337d73085c45f9416be5787d86 -a find-all

  # Use Kerberos
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 -k -a find-all

  # Use LDAPS
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 --use-ldaps -a find-all

Note: 
  - Guest and krbtgt accounts are automatically excluded from all operations
  - find requires -t or -tl to specify targets
  - find-all searches all disabled objects without requiring targets
  - Both find and find-all automatically analyze inbound relationships
        '''
    )

    # Action
    parser.add_argument('-a', '--action', 
                        choices=['enable', 'disable', 'find', 'find-all'],
                        help='Action to operate on disabled accounts')

    # Optional arguments
    parser.add_argument('--use-ldaps', action='store_true',
                        help='Use LDAPS instead of LDAP')
    parser.add_argument('--use-schannel', action='store_true',
                        help='Use LDAP Schannel (TLS) for certificate-based authentication')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='verbosity level (-v for verbose, -vv for debug)')

    # Authentication & Connection
    auth_group = parser.add_argument_group('authentication & connection')
    auth_group.add_argument('--dc-ip', metavar='ip address',
                           help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    auth_group.add_argument('-d', '--domain', metavar='DOMAIN',
                           help='(FQDN) domain to authenticate to')
    auth_group.add_argument('-u', '--user', metavar='USER',
                           help='user to authenticate with')
    auth_group.add_argument('-crt', '--certfile', metavar='CERTFILE',
                           help='Path to the user certificate (PEM format) for Schannel authentication')
    auth_group.add_argument('-key', '--keyfile', metavar='KEYFILE',
                           help='Path to the user private key (PEM format) for Schannel authentication')
    auth_group.add_argument('-td', '--target-domain', metavar='TARGET_DOMAIN',
                           help='Target domain (if different than the domain of the authenticating user)')
    auth_group.add_argument('--no-pass', action='store_true',
                           help="don't ask for password (useful for -k)")
    auth_group.add_argument('-p', '--password', metavar='PASSWORD',
                           help='password to authenticate with')
    auth_group.add_argument('-H', '--hashes', metavar='[LMHASH:]NTHASH',
                           help='NT/LM hashes, format is LMhash:NThash')
    auth_group.add_argument('--aes-key', metavar='hex key',
                           help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    auth_group.add_argument('-k', '--kerberos', action='store_true',
                           help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')

    # Target arguments
    target_group = parser.add_argument_group('arguments when setting -action to find, enable or disable')
    target_group.add_argument('-t', '--target', metavar='TARGET_SAMNAME',
                             help='Target account (required for find, enable, disable)')
    target_group.add_argument('-tl', '--target-list', metavar='TARGET_SAMNAME_LIST',
                             help='Path to a file with target accounts names (one per line)')
    
    # Additional options
    parser.add_argument('--force', action='store_true',
                       help='Skip confirmation prompts (for batch operations)')
    parser.add_argument('--port', type=int,
                       help='Custom LDAP port (default: 389 or 636 for LDAPS)')

    args = parser.parse_args()

    # Process hash argument
    if args.hashes:
        if ':' in args.hashes:
            args.lmhash, args.nthash = args.hashes.split(':')
        else:
            args.lmhash = 'aad3b435b51404eeaad3b435b51404ee'
            args.nthash = args.hashes
    else:
        args.lmhash = None
        args.nthash = None

    # Set ssl flag based on use_ldaps
    args.ssl = args.use_ldaps

   # Validation
    if not args.action:
        parser.error("Action (-a/--action) is required")
    
    if not args.domain:
        parser.error("Domain (-d/--domain) is required")
    
    if not args.user:
        parser.error("User (-u/--user) is required")
    
    # Check authentication method
    if not any([args.password, args.hashes, args.kerberos, args.no_pass, args.aes_key]):
        parser.error("Authentication required: use -p, -H, -k, --aes-key, or --no-pass")
    
    # Check target requirements for different actions
    if args.action in ['enable', 'disable', 'find']:
        # These actions REQUIRE targets
        if not args.target and not args.target_list:
            parser.error(f"Action '{args.action}' requires either -t or -tl")
    
    if args.action == 'find-all':
        # find-all does NOT accept targets
        if args.target or args.target_list:
            parser.error("Action 'find-all' does not accept -t or -tl (it searches all disabled objects automatically)")

    print_banner()

    try:
        tool = LazarusWakeUp(args)
        if not tool.run():
            sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Unexpected error: {e}")
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()