#!/usr/bin/env python3
"""
API Key Management Script
Usage:
    python manage_key.py set <key>                    - Set/update API key
    python manage_key.py get                          - Get current API key
    python manage_key.py list                         - List all keys
    python manage_key.py delete                       - Delete (deactivate) main key
    python manage_key.py bind-pc <hw-fingerprint>    - Bind API key to hardware fingerprint
    python manage_key.py list-pcs                     - List all authorized PCs
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from database import db

def set_key(key_value):
    """Set API key"""
    if len(key_value) <= 10:
        print("❌ Error: Key must be at least 10 characters long")
        return False
    
    if db.set_api_key(key_value, 'main'):
        print(f"✅ API key updated successfully")
        return True
    else:
        print("❌ Failed to update API key")
        return False

def get_key():
    """Get current API key"""
    key = db.get_api_key('main')
    if key:
        print(f"📋 Current API Key ({len(key)} chars):")
        print(f"   {key}")
        return True
    else:
        print("❌ No active API key found")
        return False

def list_keys():
    """List all keys"""
    keys = db.list_keys()
    if keys:
        print(f"📋 Active API Keys ({len(keys)}):")
        for key in keys:
            print(f"   - {key['key_name']} (created: {key['created_at']})")
        return True
    else:
        print("❌ No keys found")
        return False

def delete_key():
    """Delete main API key"""
    if db.delete_api_key('main'):
        print("✅ API key deactivated")
        return True
    else:
        print("❌ Failed to delete API key")
        return False

def bind_pc(hw_fingerprint, api_key=None):
    """Bind hardware fingerprint to a specific API key"""
    if len(hw_fingerprint) != 64:  # SHA256 hex is 64 chars
        print("❌ Error: Invalid hardware fingerprint format")
        print("💡 Fingerprint should be 64-character SHA256 hash")
        return False
    
    # Get the API key to bind to
    if api_key is None:
        api_key = db.get_api_key('main')
        if not api_key:
            print("❌ Error: No API key found in database")
            print("💡 Run: python manage_key.py set <your-key>")
            return False
    
    # Bind hardware to this specific API key
    if db.bind_hardware_to_key(api_key, hw_fingerprint=hw_fingerprint):
        print(f"✅ Hardware fingerprint bound to API key successfully")
        print(f"   API Key: {api_key}")
        print(f"   Fingerprint: {hw_fingerprint[:16]}...{hw_fingerprint[-16:]}")
        print(f"🔒 Includes: CPU ID + Motherboard Serial + MAC + Hostname + Platform")
        return True
    else:
        print("❌ Failed to bind hardware fingerprint")
        return False

def list_pcs():
    """List all authorized PCs (hardware bindings per API key)"""
    keys = db.list_keys()
    
    bound_keys = [k for k in keys if k.get('hw_fingerprint')]
    
    if bound_keys:
        print(f"📋 API Keys with Hardware Bindings ({len(bound_keys)}):")
        print()
        for idx, key in enumerate(bound_keys, 1):
            print(f"   {idx}. API Key: {key['key_value']}")
            fp = key['hw_fingerprint']
            print(f"      Fingerprint: {fp[:16]}...{fp[-16:]}")
            print(f"      Bound: {key.get('updated_at', key.get('created_at', 'Unknown'))}")
            print()
        return True
    else:
        print("❌ No hardware bindings found")
        print("💡 Run: python manage_key.py bind-pc <hardware-fingerprint>")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == 'set':
        if len(sys.argv) < 3:
            print("❌ Usage: python manage_key.py set <key>")
            sys.exit(1)
        success = set_key(sys.argv[2])
    elif command == 'get':
        success = get_key()
    elif command == 'list':
        success = list_keys()
    elif command == 'delete':
        success = delete_key()
    elif command == 'bind-pc':
        if len(sys.argv) < 3:
            print("❌ Usage: python manage_key.py bind-pc <hardware-fingerprint>")
            print("\n💡 To get hardware fingerprint from client, run on client:")
            print("   python -c \"import hashlib, uuid, subprocess as sp, platform; ids=[]; p1=sp.run(['wmic','cpu','get','ProcessorId'],capture_output=True,text=True,timeout=3); ids.append(p1.stdout.split('\\n')[1].strip() if p1.returncode==0 else ''); p2=sp.run(['wmic','baseboard','get','SerialNumber'],capture_output=True,text=True,timeout=3); ids.append(p2.stdout.split('\\n')[1].strip() if p2.returncode==0 else ''); ids.append(':'.join(['{:02x}'.format((uuid.getnode()>>i)&0xff) for i in range(0,12,2)][::-1])); ids.append(platform.node()); ids.extend(platform.uname()); fp=hashlib.sha256('|'.join([x for x in ids if x]).encode()).hexdigest(); print(fp)\"")
            sys.exit(1)
        success = bind_pc(sys.argv[2])
    elif command == 'list-pcs':
        success = list_pcs()
    else:
        print(f"❌ Unknown command: {command}")
        print(__doc__)
        sys.exit(1)
    
    sys.exit(0 if success else 1)

