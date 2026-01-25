#!/usr/bin/env python3

from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars
import struct

# ACE Types
ACCESS_ALLOWED_ACE_TYPE = 0x00
ACCESS_DENIED_ACE_TYPE = 0x01
ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06

# Access Rights
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000
DELETE = 0x00010000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000

# Extended Rights GUIDs
EXTENDED_RIGHTS = {
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
    "00000000-0000-0000-0000-000000000000": "All-Extended-Rights"
}

# Property Sets
PROPERTY_SETS = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "User-Account-Restrictions",
}

# ACE Flags
OBJECT_INHERIT_ACE = 0x01
CONTAINER_INHERIT_ACE = 0x02
INHERITED_ACE = 0x10

class ACEParser:
    def __init__(self, ldap_conn, logger):
        self.ldap_conn = ldap_conn
        self.logger = logger
        self.sid_cache = {}

    def parse_ntSecurityDescriptor(self, sd_bytes):
        """Parse NT Security Descriptor"""
        if not sd_bytes:
            return []

        try:
            # Parse SD structure
            # Offset 0: Revision (1 byte)
            # Offset 1: Sbz1 (1 byte)
            # Offset 2-3: Control flags (2 bytes)
            # Offset 4-7: Owner SID offset
            # Offset 8-11: Group SID offset
            # Offset 12-15: SACL offset
            # Offset 16-19: DACL offset
            
            if len(sd_bytes) < 20:
                self.logger.debug("Security descriptor too short")
                return []
            
            control_flags = struct.unpack('<H', sd_bytes[2:4])[0]
            dacl_offset = struct.unpack('<I', sd_bytes[16:20])[0]
            
            if dacl_offset == 0:
                self.logger.debug("No DACL present")
                return []

            # Parse DACL
            dacl = sd_bytes[dacl_offset:]
            
            if len(dacl) < 8:
                self.logger.debug("DACL too short")
                return []
            
            # DACL structure:
            # Offset 0: Revision (1 byte)
            # Offset 1: Sbz1 (1 byte)
            # Offset 2-3: Size (2 bytes)
            # Offset 4-5: ACE count (2 bytes)
            # Offset 6-7: Sbz2 (2 bytes)
            # Offset 8+: ACEs
            
            ace_count = struct.unpack('<H', dacl[4:6])[0]
            
            aces = []
            offset = 8
            
            for i in range(ace_count):
                if offset >= len(dacl):
                    break
                    
                ace = self.parse_ace(dacl[offset:])
                if ace and isinstance(ace, dict):
                    aces.append(ace)
                    offset += ace.get('size', 0)
                else:
                    break
            
            return aces
            
        except Exception as e:
            self.logger.error(f"Error parsing security descriptor: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return []

    def parse_ace(self, ace_bytes):
        """Parse individual ACE"""
        try:
            if len(ace_bytes) < 4:
                return None
                
            ace_type = ace_bytes[0]
            ace_flags = ace_bytes[1]
            ace_size = struct.unpack('<H', ace_bytes[2:4])[0]
            
            if ace_size > len(ace_bytes):
                self.logger.debug(f"ACE size {ace_size} exceeds available data")
                return {'size': ace_size, 'type': 'invalid'}
            
            # Parse based on ACE type
            if ace_type in [ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE]:
                return self.parse_standard_ace(ace_bytes, ace_type, ace_flags, ace_size)
            elif ace_type in [ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE]:
                return self.parse_object_ace(ace_bytes, ace_type, ace_flags, ace_size)
            else:
                return {'size': ace_size, 'type': 'unknown'}
                
        except Exception as e:
            self.logger.debug(f"Error parsing ACE: {e}")
            return None

    def parse_standard_ace(self, ace_bytes, ace_type, ace_flags, ace_size):
        """Parse standard ACCESS_ALLOWED/DENIED ACE"""
        try:
            if len(ace_bytes) < 8:
                return None
                
            access_mask = struct.unpack('<I', ace_bytes[4:8])[0]
            sid = self.parse_sid(ace_bytes[8:])
            
            if not sid:
                return None
            
            return {
                'type': 'ACCESS_ALLOWED' if ace_type == ACCESS_ALLOWED_ACE_TYPE else 'ACCESS_DENIED',
                'flags': ace_flags,
                'size': ace_size,
                'access_mask': access_mask,
                'rights': self.interpret_access_mask(access_mask),
                'sid': sid,
                'trustee': self.resolve_sid(sid),
                'inherited': bool(ace_flags & INHERITED_ACE)
            }
        except Exception as e:
            self.logger.debug(f"Error parsing standard ACE: {e}")
            return None

    def parse_object_ace(self, ace_bytes, ace_type, ace_flags, ace_size):
        """Parse object-specific ACCESS_ALLOWED_OBJECT/DENIED_OBJECT ACE"""
        try:
            if len(ace_bytes) < 12:
                return None
                
            access_mask = struct.unpack('<I', ace_bytes[4:8])[0]
            object_flags = struct.unpack('<I', ace_bytes[8:12])[0]
            
            offset = 12
            object_type = None
            inherited_object_type = None
            
            # ACE_OBJECT_TYPE_PRESENT = 0x01
            if object_flags & 0x01:
                if len(ace_bytes) < offset + 16:
                    return None
                object_type = self.parse_guid(ace_bytes[offset:offset+16])
                offset += 16
            
            # ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02
            if object_flags & 0x02:
                if len(ace_bytes) < offset + 16:
                    return None
                inherited_object_type = self.parse_guid(ace_bytes[offset:offset+16])
                offset += 16
            
            sid = self.parse_sid(ace_bytes[offset:])
            
            if not sid:
                return None
            
            return {
                'type': 'ACCESS_ALLOWED_OBJECT' if ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE else 'ACCESS_DENIED_OBJECT',
                'flags': ace_flags,
                'size': ace_size,
                'access_mask': access_mask,
                'rights': self.interpret_access_mask(access_mask),
                'object_type': object_type,
                'object_type_name': self.resolve_guid(object_type) if object_type else None,
                'inherited_object_type': inherited_object_type,
                'sid': sid,
                'trustee': self.resolve_sid(sid),
                'inherited': bool(ace_flags & INHERITED_ACE)
            }
        except Exception as e:
            self.logger.debug(f"Error parsing object ACE: {e}")
            return None

    def parse_sid(self, sid_bytes):
        """Parse binary SID to string format"""
        try:
            if not sid_bytes or len(sid_bytes) < 8:
                return None
            return format_sid(sid_bytes)
        except Exception as e:
            self.logger.debug(f"Error parsing SID: {e}")
            return None

    def parse_guid(self, guid_bytes):
        """Parse binary GUID to string format"""
        try:
            if not guid_bytes or len(guid_bytes) < 16:
                return None
                
            guid = struct.unpack('<IHH8s', guid_bytes[:16])
            guid_str = f"{guid[0]:08x}-{guid[1]:04x}-{guid[2]:04x}-"
            guid_str += ''.join([f"{b:02x}" for b in guid[3][:2]])
            guid_str += '-'
            guid_str += ''.join([f"{b:02x}" for b in guid[3][2:]])
            return guid_str
        except Exception as e:
            self.logger.debug(f"Error parsing GUID: {e}")
            return None

    def resolve_sid(self, sid):
        """Resolve SID to account name"""
        if not sid:
            return "Unknown"
        
        if sid in self.sid_cache:
            return self.sid_cache[sid]
        
        try:
            # Well-known SIDs
            well_known = {
                'S-1-5-18': 'NT AUTHORITY\\SYSTEM',
                'S-1-5-32-544': 'BUILTIN\\Administrators',
                'S-1-5-32-545': 'BUILTIN\\Users',
                'S-1-1-0': 'Everyone',
                'S-1-5-11': 'Authenticated Users',
                'S-1-5-9': 'Enterprise Domain Controllers',
            }
            
            if sid in well_known:
                self.sid_cache[sid] = well_known[sid]
                return well_known[sid]
            
            # Query LDAP for SID
            search_filter = f"(objectSid={sid})"
            entries = self.ldap_conn.search(search_filter, ['sAMAccountName', 'distinguishedName'])
            
            if entries:
                sam = str(entries[0].sAMAccountName) if entries[0].sAMAccountName else None
                if sam:
                    name = f"{self.ldap_conn.domain}\\{sam}"
                    self.sid_cache[sid] = name
                    return name
            
            self.sid_cache[sid] = sid
            return sid
            
        except Exception as e:
            self.logger.debug(f"Error resolving SID {sid}: {e}")
            return sid

    def resolve_guid(self, guid):
        """Resolve GUID to name"""
        if not guid:
            return None
        
        # Check extended rights
        if guid in EXTENDED_RIGHTS:
            return EXTENDED_RIGHTS[guid]
        
        # Check property sets
        if guid in PROPERTY_SETS:
            return PROPERTY_SETS[guid]
        
        return guid

    def interpret_access_mask(self, mask):
        """Interpret access mask to readable rights"""
        if not isinstance(mask, int):
            return []
            
        rights = []
        
        if mask & GENERIC_ALL:
            rights.append("GenericAll")
        if mask & GENERIC_WRITE:
            rights.append("GenericWrite")
        if mask & GENERIC_READ:
            rights.append("GenericRead")
        if mask & GENERIC_EXECUTE:
            rights.append("GenericExecute")
        if mask & WRITE_DACL:
            rights.append("WriteDacl")
        if mask & WRITE_OWNER:
            rights.append("WriteOwner")
        if mask & DELETE:
            rights.append("Delete")
        
        # ADS specific rights
        if mask & 0x00000001:
            rights.append("CreateChild")
        if mask & 0x00000002:
            rights.append("DeleteChild")
        if mask & 0x00000004:
            rights.append("ListChildren")
        if mask & 0x00000008:
            rights.append("Self")
        if mask & 0x00000010:
            rights.append("ReadProperty")
        if mask & 0x00000020:
            rights.append("WriteProperty")
        if mask & 0x00000100:
            rights.append("ExtendedRight")
        
        return rights if rights else [f"0x{mask:08x}"]