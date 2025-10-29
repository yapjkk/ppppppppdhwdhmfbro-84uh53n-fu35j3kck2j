"""
Encrypted Fingerprint System for xC-client
Generates encrypted hardware fingerprints that can be bound to API keys
"""

import platform
import socket
import hashlib
import base64
import json
from datetime import datetime
from typing import Dict, Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import subprocess as sp


class EncryptedFingerprint:
    """Create and validate encrypted hardware fingerprints"""
    
    def __init__(self, api_key: str):
        """Initialize with API key for encryption"""
        self.api_key = api_key
        self.encryption_key = self._derive_key(api_key)
    
    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from API key"""
        key = password.encode()
        for _ in range(1000):  # Iterate for security
            key = hashlib.sha256(key).digest()
        return key  # Use first 32 bytes for AES-256
    
    def get_cpu_info(self) -> Dict[str, str]:
        """Get CPU information"""
        try:
            cpu_info = {}
            
            if platform.system() == 'Windows':
                # CPU Name
                try:
                    result = sp.run(['wmic','cpu','get','Name'], capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and len(result.stdout.split('\n')) > 1:
                        cpu_info['model'] = result.stdout.split('\n')[1].strip()
                except: pass
                
                # Processor ID
                try:
                    result = sp.run(['wmic','cpu','get','ProcessorId'], capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and len(result.stdout.split('\n')) > 1:
                        cpu_id = result.stdout.split('\n')[1].strip()
                        if cpu_id:
                            cpu_info['processor_id'] = cpu_id
                except: pass
                
                # Cores
                cpu_info['cores'] = str(sp.cpu_count(logical=False))
                cpu_info['cores_logical'] = str(sp.cpu_count(logical=True))
            else:
                import psutil
                cpu_info['cores'] = str(psutil.cpu_count(logical=False))
                cpu_info['cores_logical'] = str(psutil.cpu_count(logical=True))
            
            return cpu_info
        except Exception as e:
            return {'error': str(e)}
    
    def get_memory_info(self) -> Dict[str, str]:
        """Get memory information"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            return {
                'total_gb': str(round(memory.total / (1024**3), 2)),
            }
        except:
            if platform.system() == 'Windows':
                try:
                    result = sp.run(['wmic','computersystem','get','TotalPhysicalMemory'], 
                                   capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and len(result.stdout.split('\n')) > 1:
                        total = result.stdout.split('\n')[1].strip()
                        return {'total_gb': str(round(int(total) / (1024**3), 2))}
                except: pass
            return {'error': 'unknown'}
    
    def get_disk_info(self) -> Dict[str, str]:
        """Get disk information"""
        try:
            if platform.system() == 'Windows':
                # Local Disk Serial
                try:
                    result = sp.run(['wmic','logicaldisk','where','DeviceID="C:"','get','VolumeSerialNumber'], 
                                  capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and len(result.stdout.split('\n')) > 1:
                        disk_serial = result.stdout.split('\n')[1].strip()
                        return {'disk_serial': disk_serial}
                except: pass
            return {}
        except:
            return {}
    
    def get_network_info(self) -> Dict[str, str]:
        """Get network information"""
        try:
            # MAC Address
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode()>>i)&0xff) for i in range(0,12,2)][::-1])
            return {
                'mac': mac,
                'hostname': socket.gethostname(),
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_system_info(self) -> Dict[str, str]:
        """Get system information"""
        try:
            system_info = {
                'system': platform.system(),
                'release': platform.release(),
                'machine': platform.machine(),
            }
            
            # Windows specific
            if platform.system() == 'Windows':
                # Device UUID
                try:
                    result = sp.run(['wmic','csproduct','get','UUID'], capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and len(result.stdout.split('\n')) > 1:
                        system_info['uuid'] = result.stdout.split('\n')[1].strip()
                except: pass
                
                # Product ID
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                    product_id, _ = winreg.QueryValueEx(key, "ProductId")
                    system_info['product_id'] = product_id
                    winreg.CloseKey(key)
                except: pass
                
                # Motherboard Serial
                try:
                    result = sp.run(['wmic','baseboard','get','SerialNumber'], capture_output=True, text=True, timeout=3)
                    if result.returncode == 0 and len(result.stdout.split('\n')) > 1:
                        mb_serial = result.stdout.split('\n')[1].strip()
                        if mb_serial:
                            system_info['mb_serial'] = mb_serial
                except: pass
                
                # Device Name
                try:
                    result = sp.run(['hostname'], capture_output=True, text=True, timeout=2)
                    if result.returncode == 0:
                        system_info['device_name'] = result.stdout.strip()
                except: pass
            
            return system_info
        except Exception as e:
            return {'error': str(e)}
    
    def get_machine_id(self) -> str:
        """Get machine ID"""
        try:
            if platform.system() == "Windows":
                result = sp.run(['reg', 'query', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography', 
                               '/v', 'MachineGuid'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'MachineGuid' in line:
                            return line.split()[-1]
        except:
            pass
        
        # Fallback to UUID
        import uuid
        return str(uuid.uuid1())
    
    def collect_fingerprint_data(self) -> Dict:
        """Collect all hardware fingerprint data"""
        return {
            'cpu': self.get_cpu_info(),
            'memory': self.get_memory_info(),
            'disk': self.get_disk_info(),
            'network': self.get_network_info(),
            'system': self.get_system_info(),
            'machine_id': self.get_machine_id(),
            'timestamp': datetime.now().isoformat(),
        }
    
    def generate_encrypted_fingerprint(self) -> str:
        """Generate encrypted fingerprint string for current machine"""
        # Collect hardware data
        fingerprint_data = self.collect_fingerprint_data()
        
        # Create payload
        payload = {
            'fingerprint': fingerprint_data,
            'timestamp': datetime.now().isoformat(),
            'version': '1.0'
        }
        
        # Convert to JSON
        json_data = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        
        # Encrypt using AES-256-CBC
        iv = get_random_bytes(16)
        cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
        
        # Pad the data
        from Crypto.Util.Padding import pad
        padded_data = pad(json_data.encode('utf-8'), AES.block_size)
        
        # Encrypt
        encrypted = cipher.encrypt(padded_data)
        
        # Combine IV and encrypted data
        combined = iv + encrypted
        
        # Encode to base64
        encrypted_string = base64.urlsafe_b64encode(combined).decode('utf-8')
        
        return encrypted_string
    
    def decrypt_and_validate_fingerprint(self, encrypted_string: str, current_hw_data: Dict = None) -> Tuple[bool, str, Dict]:
        """
        Decrypt fingerprint and validate against current hardware
        
        Returns:
            (is_valid, message, fingerprint_data)
        """
        try:
            # Strip whitespace
            encrypted_string = encrypted_string.strip()
            
            # Decode from base64
            try:
                combined = base64.urlsafe_b64decode(encrypted_string.encode('utf-8'))
            except Exception as e:
                return False, f"Invalid fingerprint format: {str(e)}", {}
            
            # Split IV and encrypted data
            iv = combined[:16]
            encrypted = combined[16:]
            
            # Decrypt
            try:
                cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted)
                
                # Unpad
                from Crypto.Util.Padding import unpad
                decrypted_json = unpad(decrypted, AES.block_size).decode('utf-8')
            except Exception as e:
                return False, f"Decryption failed: {str(e)}", {}
            
            # Parse JSON
            try:
                fingerprint_data = json.loads(decrypted_json)
            except Exception as e:
                return False, f"Invalid fingerprint data: {str(e)}", {}
            
            # If no current hardware provided, just return the decrypted data
            if current_hw_data is None:
                return True, "Fingerprint decrypted successfully", fingerprint_data
            
            # Validate against current hardware
            stored_fingerprint = fingerprint_data['fingerprint']
            mismatch_fields = []
            
            # Compare key identifiers
            # Machine ID
            if current_hw_data.get('machine_id') != stored_fingerprint.get('machine_id'):
                mismatch_fields.append('machine_id')
            
            # CPU
            if current_hw_data.get('cpu', {}).get('processor_id') != stored_fingerprint.get('cpu', {}).get('processor_id'):
                if stored_fingerprint.get('cpu', {}).get('processor_id'):
                    mismatch_fields.append('cpu_processor_id')
            
            # UUID
            if current_hw_data.get('system', {}).get('uuid') != stored_fingerprint.get('system', {}).get('uuid'):
                if stored_fingerprint.get('system', {}).get('uuid'):
                    mismatch_fields.append('uuid')
            
            # Product ID
            if current_hw_data.get('system', {}).get('product_id') != stored_fingerprint.get('system', {}).get('product_id'):
                if stored_fingerprint.get('system', {}).get('product_id'):
                    mismatch_fields.append('product_id')
            
            # MB Serial
            if current_hw_data.get('system', {}).get('mb_serial') != stored_fingerprint.get('system', {}).get('mb_serial'):
                if stored_fingerprint.get('system', {}).get('mb_serial'):
                    mismatch_fields.append('mb_serial')
            
            # Disk Serial
            if current_hw_data.get('disk', {}).get('disk_serial') != stored_fingerprint.get('disk', {}).get('disk_serial'):
                if stored_fingerprint.get('disk', {}).get('disk_serial'):
                    mismatch_fields.append('disk_serial')
            
            if mismatch_fields:
                return False, f"Hardware mismatch: {', '.join(mismatch_fields)}", fingerprint_data
            
            return True, "Fingerprint matches current hardware", fingerprint_data
            
        except Exception as e:
            return False, f"Validation error: {str(e)}", {}


# Try to import psutil, but don't fail if not available
try:
    import psutil
    import sp
    sp.cpu_count = lambda logical=False: psutil.cpu_count(logical=logical)
except:
    pass

