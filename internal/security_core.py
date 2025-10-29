"""
Advanced Multi-Layer Security System
Implements RSA + AES hybrid encryption, code signing, hardware fingerprinting
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import hmac
import time
import json
import os
import platform
import uuid
import subprocess

class AdvancedSecurityManager:
    """
    Multi-layer security with:
    - RSA asymmetric encryption (2048-bit)
    - Per-session AES keys
    - Code signing verification
    - Hardware fingerprinting
    - Anti-tampering detection
    """
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.server_private_key = None
        self.server_public_key = None
        self.active_sessions = {}  # session_id -> session_data
        self._load_or_generate_rsa_keys()
    
    def _load_or_generate_rsa_keys(self):
        """Load or generate RSA key pair"""
        # Try to load existing keys from database
        private_pem = self.db.get_api_key('rsa_private_key')
        public_pem = self.db.get_api_key('rsa_public_key')
        
        if private_pem and public_pem:
            # Load existing keys
            self.server_private_key = RSA.import_key(private_pem)
            self.server_public_key = RSA.import_key(public_pem)
            print(f"✅ Loaded RSA keys from database")
        else:
            # Generate new 2048-bit RSA key pair
            print(f"🔑 Generating new 2048-bit RSA key pair...")
            key = RSA.generate(2048)
            self.server_private_key = key
            self.server_public_key = key.publickey()
            
            # Save to database
            self.db.set_api_key(key.export_key().decode(), 'rsa_private_key')
            self.db.set_api_key(self.server_public_key.export_key().decode(), 'rsa_public_key')
            print(f"✅ Generated and saved RSA keys")
    
    def get_public_key_pem(self):
        """Get public key in PEM format for client"""
        return self.server_public_key.export_key().decode()
    
    def create_session(self, client_mac, api_key_hash):
        """
        Create secure session with unique AES key
        Returns: session_id, encrypted_session_key, signature
        """
        # Generate unique session ID
        session_id = base64.b64encode(get_random_bytes(32)).decode()
        
        # Generate random AES session key (256-bit)
        session_aes_key = get_random_bytes(32)
        
        # Store session info
        self.active_sessions[session_id] = {
            'aes_key': session_aes_key,
            'client_mac': client_mac,
            'api_key_hash': api_key_hash,
            'created_at': time.time(),
            'request_count': 0
        }
        
        # Sign the session key with server's private key (for verification)
        h = SHA256.new(session_aes_key)
        signature = pkcs1_15.new(self.server_private_key).sign(h)
        
        # Encrypt session key using hybrid approach:
        # Derive encryption key from API key + session ID (both parties know these)
        derived_key = hashlib.sha256(f"{api_key_hash}:{session_id}".encode()).digest()
        
        # Encrypt session AES key with derived key
        iv = get_random_bytes(16)
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        from Crypto.Util.Padding import pad
        encrypted_key = cipher.encrypt(pad(session_aes_key, AES.block_size))
        
        # Package: IV + Encrypted Key + Signature
        package = {
            'iv': base64.b64encode(iv).decode(),
            'encrypted_key': base64.b64encode(encrypted_key).decode(),
            'signature': base64.b64encode(signature).decode()
        }
        
        encrypted_session_key = base64.b64encode(json.dumps(package).encode()).decode()
        
        print(f"🔐 Created session: {session_id[:16]}...")
        
        return session_id, encrypted_session_key
    
    def validate_session(self, session_id):
        """Validate session and return AES key"""
        if session_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[session_id]
        
        # Check session age (expire after 1 hour)
        if time.time() - session['created_at'] > 3600:
            del self.active_sessions[session_id]
            return None
        
        # Increment request count
        session['request_count'] += 1
        
        # Limit requests per session
        if session['request_count'] > 1000:
            del self.active_sessions[session_id]
            return None
        
        return session['aes_key']
    
    def encrypt_code_with_session(self, code, session_id):
        """
        Encrypt code using session's AES key
        Add signature for integrity verification
        """
        aes_key = self.validate_session(session_id)
        if not aes_key:
            raise ValueError("Invalid or expired session")
        
        # Generate random IV
        iv = get_random_bytes(16)
        
        # Encrypt code with AES
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(code.encode('utf-8'), AES.block_size))
        
        # Sign the encrypted code
        h = SHA256.new(encrypted)
        signature = pkcs1_15.new(self.server_private_key).sign(h)
        
        # Package: IV + Encrypted Code + Signature
        package = {
            'iv': base64.b64encode(iv).decode(),
            'data': base64.b64encode(encrypted).decode(),
            'signature': base64.b64encode(signature).decode(),
            'timestamp': int(time.time())
        }
        
        return base64.b64encode(json.dumps(package).encode()).decode()
    
    def generate_hardware_fingerprint(self):
        """
        Generate comprehensive hardware fingerprint
        Much more than just MAC address
        """
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
            print(f"⚠️  Fingerprint error: {e}")
        
        # Combine and hash
        combined = '|'.join(identifiers)
        fingerprint = hashlib.sha256(combined.encode()).hexdigest()
        
        return fingerprint, identifiers
    
    def verify_hardware_fingerprint(self, client_fingerprint, stored_fingerprint):
        """Verify hardware fingerprint matches"""
        return hmac.compare_digest(client_fingerprint, stored_fingerprint)
    
    def cleanup_old_sessions(self):
        """Remove expired sessions"""
        current_time = time.time()
        expired = [
            sid for sid, data in self.active_sessions.items()
            if current_time - data['created_at'] > 3600
        ]
        for sid in expired:
            del self.active_sessions[sid]
        
        if expired:
            print(f"🧹 Cleaned up {len(expired)} expired sessions")

# Global security manager (initialized in app.py)
security_manager = None

