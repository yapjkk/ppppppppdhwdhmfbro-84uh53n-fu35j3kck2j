"""
Client-side Security Module
Handles RSA decryption, session management, anti-debugging
To be sent to client for local use
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
import base64
import json
import hashlib
import uuid
import platform
import subprocess
import time
import sys

class ClientSecurityHandler:
    """Client-side security handler"""
    
    def __init__(self, server_public_key_pem, api_key):
        self.server_public_key = RSA.import_key(server_public_key_pem)
        self.api_key = api_key
        self.api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        self.session_id = None
        self.session_key = None
        self._anti_debug_check()
    
    def _anti_debug_check(self):
        """Detect if code is being debugged/analyzed"""
        # Check for debugger
        if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
            print("⚠️  Debugger detected")
            # In production, you might want to exit or obfuscate more
        
        # Check for common analysis tools
        suspicious_processes = ['ida', 'ollydbg', 'x64dbg', 'ghidra', 'wireshark']
        try:
            if platform.system() == 'Windows':
                tasklist = subprocess.check_output('tasklist', text=True).lower()
                for proc in suspicious_processes:
                    if proc in tasklist:
                        print(f"⚠️  Suspicious process detected: {proc}")
        except:
            pass
    
    def generate_hardware_fingerprint(self):
        """Generate same fingerprint as server expects"""
        identifiers = []
        
        try:
            # CPU info
            if platform.system() == 'Windows':
                proc = subprocess.run(['wmic', 'cpu', 'get', 'ProcessorId'], 
                                    capture_output=True, text=True, timeout=5)
                if proc.returncode == 0:
                    cpu_id = proc.stdout.split('\n')[1].strip()
                    identifiers.append(f"CPU:{cpu_id}")
            
            # Motherboard serial
            if platform.system() == 'Windows':
                proc = subprocess.run(['wmic', 'baseboard', 'get', 'SerialNumber'], 
                                    capture_output=True, text=True, timeout=5)
                if proc.returncode == 0:
                    mb_serial = proc.stdout.split('\n')[1].strip()
                    identifiers.append(f"MB:{mb_serial}")
            
            # MAC address
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) 
                           for i in range(0,2*6,2)][::-1])
            identifiers.append(f"MAC:{mac}")
            
            # Machine UUID (Linux)
            if platform.system() == 'Linux':
                try:
                    with open('/etc/machine-id', 'r') as f:
                        identifiers.append(f"MID:{f.read().strip()}")
                except:
                    pass
            
            # Hostname
            identifiers.append(f"HOST:{platform.node()}")
            
        except Exception as e:
            pass
        
        # Combine and hash
        combined = '|'.join(identifiers)
        fingerprint = hashlib.sha256(combined.encode()).hexdigest()
        
        return fingerprint
    
    def decrypt_session_key(self, encrypted_session_key_b64, session_id):
        """Decrypt session key and verify signature"""
        try:
            # Decode package
            package_json = base64.b64decode(encrypted_session_key_b64).decode()
            package = json.loads(package_json)
            
            # Extract components
            iv = base64.b64decode(package['iv'])
            encrypted_key = base64.b64decode(package['encrypted_key'])
            signature = base64.b64decode(package['signature'])
            
            # Derive decryption key (same as server)
            derived_key = hashlib.sha256(f"{self.api_key_hash}:{session_id}".encode()).digest()
            
            # Decrypt session key
            cipher = AES.new(derived_key, AES.MODE_CBC, iv)
            self.session_key = unpad(cipher.decrypt(encrypted_key), AES.block_size)
            
            # Verify signature
            h = SHA256.new(self.session_key)
            try:
                pkcs1_15.new(self.server_public_key).verify(h, signature)
            except Exception:
                raise ValueError("Session key signature verification failed!")
            
            return True
            
        except Exception as e:
            print(f"Failed to decrypt session key: {e}")
            return False
    
    def decrypt_code(self, encrypted_package_b64):
        """
        Decrypt code package and verify signature
        """
        if not self.session_key:
            raise ValueError("No session key available")
        
        try:
            # Decode base64 package
            package_json = base64.b64decode(encrypted_package_b64).decode()
            package = json.loads(package_json)
            
            # Extract components
            iv = base64.b64decode(package['iv'])
            encrypted_data = base64.b64decode(package['data'])
            signature = base64.b64decode(package['signature'])
            timestamp = package['timestamp']
            
            # Verify timestamp (prevent replay)
            if abs(time.time() - timestamp) > 300:  # 5 minutes
                raise ValueError("Package timestamp expired")
            
            # Verify signature
            h = SHA256.new(encrypted_data)
            try:
                pkcs1_15.new(self.server_public_key).verify(h, signature)
            except Exception:
                raise ValueError("Signature verification failed - code may be tampered!")
            
            # Decrypt with session AES key
            cipher = AES.new(self.session_key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            
            return decrypted.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def set_session(self, session_id, encrypted_session_key):
        """Set session ID and decrypt session key"""
        self.session_id = session_id
        return self.decrypt_session_key(encrypted_session_key, session_id)

# Helper function to export for client
def get_client_security_code():
    """Return this module's source code for client"""
    import inspect
    return inspect.getsource(sys.modules[__name__])

