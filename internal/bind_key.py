#!/usr/bin/env python3
"""
Bind API Key + Hardware Fingerprint in One Step
Usage:
    python bind_key.py "xCproduction888|5ae02b47547a342b27018488123ef1838aa3f8979567720dac6c2e6604768c83"
    python bind_key.py xCproduction888 5ae02b47547a342b27018488123ef1838aa3f8979567720dac6c2e6604768c83
    
Or from a file:
    python bind_key.py bindings.txt
    
File format (bindings.txt):
    xCproduction888|5ae02b47547a342b27018488123ef1838aa3f8979567720dac6c2e6604768c83
    xCclient222222|7df8e9c01234abcd5678ef90abcd1234567890abcdef1234567890abcdef1234
    xCtest12345|abc123def456...
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from database import db
import json

def validate_fingerprint(fp):
    """Validate fingerprint format"""
    if not fp or len(fp) != 64:
        return False
    try:
        int(fp, 16)  # Must be valid hex
        return True
    except:
        return False

def bind_key_fingerprint(api_key, fingerprint, overwrite=False):
    """Bind an API key to a hardware fingerprint"""
    
    # Validate inputs
    if not api_key or len(api_key) < 10:
        print(f"❌ Error: API key must be at least 10 characters")
        return False
    
    if not validate_fingerprint(fingerprint):
        print(f"❌ Error: Invalid fingerprint format")
        print(f"   Expected: 64-character hex string (SHA256)")
        print(f"   Got: {len(fingerprint)} characters")
        return False
    
    # Set the API key (creates if doesn't exist)
    existing = db.get_api_key('main')
    if existing and existing != api_key:
        if not overwrite:
            print(f"\n⚠️  WARNING: Different API key already exists!")
            print(f"   Current: {existing}")
            print(f"   New:     {api_key}")
            response = input("   Overwrite? (yes/no): ")
            if response.lower() != 'yes':
                print("   Cancelled.")
                return False
    
    # Set the API key
    if not db.set_api_key(api_key, 'main'):
        print(f"❌ Failed to set API key")
        return False
    
    print(f"✅ API key set: {api_key}")
    
    # Check if hardware is already bound to this key
    hw_binding = db.get_hardware_for_key(api_key)
    if hw_binding and hw_binding['hw_fingerprint']:
        if not overwrite:
            print(f"\n⚠️  WARNING: Hardware already bound to this key!")
            print(f"   Current: {hw_binding['hw_fingerprint'][:16]}...{hw_binding['hw_fingerprint'][-16:]}")
            print(f"   New:     {fingerprint[:16]}...{fingerprint[-16:]}")
            response = input("   Overwrite? (yes/no): ")
            if response.lower() != 'yes':
                print("   Cancelled.")
                return False
    
    # Bind hardware to this API key
    if not db.bind_hardware_to_key(api_key, hw_fingerprint=fingerprint):
        print(f"❌ Failed to bind hardware")
        return False
    
    print(f"✅ Hardware bound: {fingerprint[:16]}...{fingerprint[-16:]}")
    print()
    print(f"🎉 SUCCESS! API key '{api_key}' is now bound to this PC")
    print(f"🔒 Only this PC can use this API key")
    print()
    
    return True

def process_binding_string(binding_str):
    """Process a binding string in format: api_key|fingerprint"""
    parts = binding_str.split('|')
    if len(parts) != 2:
        print(f"❌ Error: Invalid format")
        print(f"   Expected: api_key|fingerprint")
        print(f"   Got: {binding_str}")
        return False
    
    api_key = parts[0].strip()
    fingerprint = parts[1].strip()
    
    return bind_key_fingerprint(api_key, fingerprint)

def process_file(filename):
    """Process a file with multiple bindings"""
    if not os.path.exists(filename):
        print(f"❌ Error: File not found: {filename}")
        return False
    
    print(f"\n📄 Processing bindings from: {filename}")
    print("=" * 70)
    
    with open(filename, 'r') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if not lines:
        print(f"❌ No bindings found in file")
        return False
    
    print(f"\n📋 Found {len(lines)} binding(s)")
    print()
    
    success_count = 0
    for idx, line in enumerate(lines, 1):
        print(f"\n[{idx}/{len(lines)}] Processing: {line[:50]}...")
        print("-" * 70)
        if process_binding_string(line):
            success_count += 1
    
    print("\n" + "=" * 70)
    print(f"✅ Successfully bound: {success_count}/{len(lines)}")
    print()
    
    return success_count > 0

def show_current_bindings():
    """Show all current bindings"""
    print("\n📋 CURRENT API KEY BINDINGS")
    print("=" * 70)
    
    keys = db.list_keys()
    bound_keys = [k for k in keys if k['hw_fingerprint']]
    
    if not bound_keys:
        print("\n❌ No bindings found")
        print("💡 Create one with:")
        print("   python bind_key.py 'api_key|fingerprint'")
        return
    
    print(f"\n🔒 Found {len(bound_keys)} bound key(s):\n")
    for idx, key in enumerate(bound_keys, 1):
        print(f"{idx}. API Key: {key['key_value']}")
        print(f"   Fingerprint: {key['hw_fingerprint'][:16]}...{key['hw_fingerprint'][-16:]}")
        print(f"   Bound: {key['updated_at'] if key['updated_at'] else key['created_at']}")
        print()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        print("\n" + "=" * 70)
        show_current_bindings()
        sys.exit(1)
    
    arg1 = sys.argv[1]
    
    # Check if it's a command
    if arg1 in ['list', 'show', 'status']:
        show_current_bindings()
        sys.exit(0)
    
    # Check if it's a file
    if os.path.isfile(arg1):
        success = process_file(arg1)
        sys.exit(0 if success else 1)
    
    # Check if it's pipe-separated format
    if '|' in arg1:
        success = process_binding_string(arg1)
        sys.exit(0 if success else 1)
    
    # Check if it's two separate arguments
    if len(sys.argv) >= 3:
        api_key = sys.argv[1]
        fingerprint = sys.argv[2]
        success = bind_key_fingerprint(api_key, fingerprint)
        sys.exit(0 if success else 1)
    
    # Invalid usage
    print("❌ Invalid usage")
    print(__doc__)
    sys.exit(1)
