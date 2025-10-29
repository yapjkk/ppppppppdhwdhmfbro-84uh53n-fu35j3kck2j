from flask import Flask, request , render_template , redirect , flash , session, make_response ,url_for, abort
from werkzeug.utils  import secure_filename
from werkzeug.security import generate_password_hash , check_password_hash
import datetime
import os
import sys
import json
from core import config
from core.mysql import mysql
from core.posts import postsDB
from database import db
import hashlib
import hmac
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Import advanced security
from security_core import AdvancedSecurityManager, security_manager
import client_security

app = Flask(__name__)
app.config.from_object(config.DevelopmentConfig) # All config now in config.py object

# Initialize security manager
security_mgr = None

# Load API key from database
def load_api_key():
    """Load API key from database - NO AUTO-CREATE"""
    try:
        # Get key from database - if not found, EXIT
        key = db.get_api_key('main')
        
        if not key or len(key) <= 10:
            print(f"❌ ERROR: No valid API key found in database!")
            print(f"💡 Run: python manage_key.py set 'your-key-here'")
            sys.exit(1)
        
        print(f"✅ API Key loaded from database ({len(key)} chars)")
        return key
        
    except Exception as e:
        print(f"❌ ERROR loading API key: {e}")
        sys.exit(1)

# Security configuration
API_KEY = load_api_key()  # Load from database - auto-created if needed
ENCRYPTION_KEY = hashlib.sha256(API_KEY.encode()).digest()  # 32 bytes for AES-256 (legacy)
print(f"✅ Encryption configured")

# Initialize advanced security manager
security_mgr = AdvancedSecurityManager(db)
print(f"✅ Advanced security initialized")

def verify_api_key(request):
    """Verify the API key from request headers"""
    api_key = request.headers.get('X-API-Key')
    timestamp = request.headers.get('X-Timestamp')
    
    # Debug logging
    print(f"\n🔐 API Request:")
    print(f"   Endpoint: {request.path}")
    print(f"   API Key: {api_key[:20]}..." if api_key else "   API Key: MISSING")
    print(f"   Timestamp: {timestamp}")
    
    if not api_key or not timestamp:
        print(f"❌ Missing API key or timestamp")
        return False
    
    # Verify timestamp (prevent replay attacks - allow 5 minutes window)
    try:
        req_time = int(timestamp)
        current_time = int(time.time())
        if abs(current_time - req_time) > 300:  # 5 minutes
            return False
    except:
        return False
    
    # Verify API key signature
    expected_signature = hmac.new(
        API_KEY.encode(),
        timestamp.encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(api_key, expected_signature):
        return False
    
    print(f"✅ Request authorized\n")
    return True

def encrypt_code(code):
    """Encrypt code using AES-256"""
    try:
        from Crypto.Random import get_random_bytes
        iv = get_random_bytes(16)
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(code.encode('utf-8'), AES.block_size))
        encrypted_data = iv + encrypted
        return base64.b64encode(encrypted_data).decode('utf-8')
    except Exception as e:
        return code  # Return unencrypted if encryption fails

# Module routes
module_names = [
    'b2riad', 'custom', 'email_logger', 'email_utils', 'fmswitch',
    'listener', 'loader', 'placeholders', 'punnnycode', 'send_email',
    'send_threaded', 'smtp_load_balancer'
]

# Get the base directory - try multiple possible locations
_current_dir = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(_current_dir)  # Go up one level from internal/

# Try to find xC directory - search in multiple locations
xC_PATHS = []
if os.path.exists('/root/SNEREDER/xC'):
    xC_PATHS.append('/root/SNEREDER/xC')
if os.path.exists(os.path.join(BASE_DIR, 'xC')):
    xC_PATHS.append(os.path.join(BASE_DIR, 'xC'))
if os.path.exists(os.path.join(os.path.dirname(BASE_DIR), 'xC')):
    xC_PATHS.append(os.path.join(os.path.dirname(BASE_DIR), 'xC'))

# Alternative paths to try - prioritize actual Python files
POSSIBLE_PATHS = []
for xc_path in xC_PATHS:
    POSSIBLE_PATHS.append(xc_path)  # Add xC paths first
POSSIBLE_PATHS.extend([
    os.path.join(BASE_DIR, 'internal'),  # /root/SNEREDER/internal (has .txt files)
    BASE_DIR,  # /root/SNEREDER
])

# ============================================================================
# ADVANCED SECURITY ENDPOINTS
# ============================================================================

@app.route('/security/handshake', methods=['POST'])
def security_handshake():
    """
    Initial handshake - client gets public key and creates session
    Step 1 of secure communication
    """
    # Verify API key
    result = verify_api_key(request)
    if result != True:
        if isinstance(result, str):
            return {"error": result}, 401
        return {"error": "Unauthorized"}, 401
    
    try:
        # Get client info
        data = request.get_json() or {}
        client_info = data.get('client_info', {})
        
        # Log client info
        print(f"\n🤝 Handshake request from client:")
        print(f"   Platform: {client_info.get('platform', 'unknown')}")
        print(f"   Platform Version: {client_info.get('platform_version', 'unknown')}")
        print(f"   Python Version: {client_info.get('python_version', 'unknown')}")
        
        # Get API key hash for session
        api_key_hash = hashlib.sha256(API_KEY.encode()).hexdigest()
        
        # Create session
        session_id, encrypted_session_key = security_mgr.create_session(
            "server-side-validation", api_key_hash
        )
        
        return {
            'status': 'success',
            'session_id': session_id,
            'session_key': encrypted_session_key,
            'server_public_key': security_mgr.get_public_key_pem(),
            'expires_in': 3600
        }, 200
        
    except Exception as e:
        return {"error": f"Handshake failed: {str(e)}"}, 500

@app.route('/security/client-handler', methods=['GET'])
def get_client_security_handler():
    """
    Send client security handler code
    Client needs this to handle encryption/decryption
    """
    # Verify API key
    result = verify_api_key(request)
    if result != True:
        return "Unauthorized", 401
    
    try:
        # Return client security module source code
        return client_security.get_client_security_code(), 200, {
            'Content-Type': 'text/plain; charset=utf-8'
        }
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/security/ultra-compact', methods=['GET', 'POST'])
def ultra_compact_client():
    """
    Ultra-compact client endpoint - returns compressed one-liner
    """
    # Verify API key
    result = verify_api_key(request)
    if result != True:
        return "Unauthorized", 401
    
    try:
        # Get client info if provided
        client_data = {}
        if request.method == 'POST':
            client_data = request.get_json() or request.form.to_dict()
        
        # Log client info
        hw_fp = client_data.get('hardware_fingerprint', 'unknown')
        client_platform = client_data.get('platform', 'unknown')
        print(f"🔐 Ultra-compact request from: {hw_fp[:16]}... | {client_platform}")
        
        # Read the ultra-compact client
        ultra_client_path = os.path.join(os.path.dirname(BASE_DIR), 'xc_ultra.py')
        if not os.path.exists(ultra_client_path):
            ultra_client_path = os.path.join(BASE_DIR, 'xc_ultra.py')
        
        if os.path.exists(ultra_client_path):
            with open(ultra_client_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # Return raw code (client decides compression)
            return code, 200, {'Content-Type': 'text/plain; charset=utf-8'}
        else:
            return "Ultra-compact client not found", 404
            
    except Exception as e:
        return f"Error: {str(e)}", 500

# ============================================================================
# MODULE ROUTES (with advanced security)
# ============================================================================

# Create routes for all modules
def create_module_route(module_name):
    @app.route(f'/{module_name}', methods=['GET', 'POST'], endpoint=f'{module_name}_route')
    def route_handler():
        # Verify API key
        result = verify_api_key(request)
        if result != True:  # If it's not True, it's an error message
            if isinstance(result, str):
                return f"Unauthorized: {result}", 401
            else:
                return "Unauthorized: Invalid or missing API key", 401
        
        try:
            # Try all possible paths with both .py and .txt extensions
            for base in POSSIBLE_PATHS:
                for ext in ['.py', '.txt']:
                    module_path = os.path.join(base, 'functions', f'{module_name}{ext}')
                    if os.path.exists(module_path):
                        with open(module_path, 'r', encoding='utf-8') as f:
                            code = f.read()
                        
                        # Check if client wants compression (ultra-compact mode)
                        compress_mode = request.headers.get('X-Compress', '').lower()
                        
                        if compress_mode == 'ultra':
                            # Ultra-compact mode: bz2 + gzip compression (no encryption)
                            import bz2, gzip
                            compressed = bz2.compress(gzip.compress(code.encode('utf-8')))
                            return compressed, 200, {
                                'Content-Type': 'application/octet-stream',
                                'X-Encryption-Type': 'compressed'
                            }
                        
                        # Check if client is using advanced security (session-based)
                        session_id = request.headers.get('X-Session-ID')
                        
                        if session_id and security_mgr:
                            # Use advanced session-based encryption
                            try:
                                encrypted_code = security_mgr.encrypt_code_with_session(code, session_id)
                                return encrypted_code, 200, {
                                    'Content-Type': 'text/plain; charset=utf-8',
                                    'X-Encryption-Type': 'advanced'
                                }
                            except Exception as e:
                                # Fall back to legacy encryption if session invalid
                                print(f"⚠️  Session encryption failed: {e}")
                                encrypted_code = encrypt_code(code)
                                return encrypted_code, 200, {
                                    'Content-Type': 'text/plain; charset=utf-8',
                                    'X-Encryption-Type': 'legacy'
                                }
                        else:
                            # Use legacy encryption for backwards compatibility
                            encrypted_code = encrypt_code(code)
                            return encrypted_code, 200, {
                                'Content-Type': 'text/plain; charset=utf-8',
                                'X-Encryption-Type': 'legacy'
                            }
            
            # If not found, return error
            return "Module not found", 404
        except Exception as e:
            return f"Error loading {module_name}: {str(e)}", 500

for module_name in module_names:
    create_module_route(module_name)


@app.route('/banner', methods=['GET'])
def banner_route():
    """Serve the ASCII art banner from banner.txt"""
    # Verify API key
    result = verify_api_key(request)
    if result != True:  # If it's not True, it's an error message
        if isinstance(result, str):
            return f"Unauthorized: {result}", 401
        else:
            return "Unauthorized: Invalid or missing API key", 401
    
    try:
        # Try multiple possible locations for banner.txt
        banner_paths = [
            os.path.join(_current_dir, 'functions', 'banner.txt'),  # internal/functions/banner.txt (current directory)
            os.path.join(os.path.dirname(__file__), 'functions', 'banner.txt'),  # From app.py location
            os.path.join(BASE_DIR, 'internal', 'functions', 'banner.txt'),  # SNEREDER/internal/functions/banner.txt
            os.path.join(BASE_DIR, 'xC', 'internal', 'functions', 'banner.txt'),  # SNEREDER/xC/internal/functions/banner.txt
            '/root/SNEREDER/internal/functions/banner.txt',  # Absolute path on server
        ]
        
        for banner_path in banner_paths:
            if os.path.exists(banner_path):
                with open(banner_path, 'r', encoding='utf-8') as f:
                    banner_code = f.read()
                
                # Encrypt before sending
                encrypted_banner = encrypt_code(banner_code)
                return encrypted_banner, 200, {'Content-Type': 'text/plain; charset=utf-8'}
        
        # If not found, return debug info
        debug_info = [f"Checked {len(banner_paths)} paths:"]
        for path in banner_paths:
            debug_info.append(f"  {path} - Exists: {os.path.exists(path)}")
        return f"Banner file not found.\n" + "\n".join(debug_info), 404
    except Exception as e:
        return f"Error loading banner: {str(e)}", 500


@app.route('/generate-credentials', methods=['GET'])
def generate_credentials():
    """Generate API credentials for testing"""
    timestamp = str(int(time.time()))
    signature = hmac.new(
        API_KEY.encode(),
        timestamp.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return {
        'apiKey': signature,
        'timestamp': timestamp
    }


@app.route('/test-api', methods=['GET'])
def test_api():
    """Serve the test API HTML page"""
    try:
        test_html_path = os.path.join(os.path.dirname(__file__), 'test.html')
        if os.path.exists(test_html_path):
            with open(test_html_path, 'r', encoding='utf-8') as f:
                return f.read()
        return "Test page not found", 404
    except Exception as e:
        return f"Error loading test page: {str(e)}", 500


@app.route('/debug', methods=['GET'])
def debug_info():
    """Debug endpoint to show file paths"""
    debug_info = []
    debug_info.append(f"BASE_DIR: {BASE_DIR}")
    debug_info.append(f"__file__: {__file__}")
    
    # Check all possible paths
    for base in POSSIBLE_PATHS:
        functions_dir = os.path.join(base, 'functions')
        debug_info.append(f"<br>Checking: {functions_dir}")
        debug_info.append(f"Exists: {os.path.exists(functions_dir)}")
        if os.path.exists(functions_dir):
            files = os.listdir(functions_dir)
            debug_info.append(f"Files: {files}")
    
    # Also check what directories exist in BASE_DIR
    if os.path.exists(BASE_DIR):
        debug_info.append(f"<br>Contents of {BASE_DIR}:")
        debug_info.append(str(os.listdir(BASE_DIR)))
    
    # Search recursively for functions directory
    debug_info.append("<br><br>Searching for 'functions' directory recursively...")
    import fnmatch
    for root, dirs, files in os.walk(BASE_DIR):
        if 'functions' in dirs:
            func_dir = os.path.join(root, 'functions')
            debug_info.append(f"Found functions dir: {func_dir}")
            debug_info.append(f"Contains: {os.listdir(func_dir)}")
            break
    
    return "<br>".join(debug_info)
    
@app.route('/', methods = ['GET','POST'])
def index():
    return "Working route. All test live"


# NOTE: Database is not configured. Commenting out blog route.
# If you need a blog, you'll need to:
# 1. Install mysql-connector-python: pip install mysql-connector-python
# 2. Configure database connection in core/mysql.py
# 3. Create database tables
# 4. Uncomment this route

# @app.route('/blog', methods = ['GET','POST'])
# def blogindex():
#     tags = mysql.getAllFromDB('tags')
#     tags = [i['tagname'] for i in tags]
#     if session.get('logged_in') : 
#         user = session['logged_in']
#     else:
#         user = "guest"
#     posts = postsDB(mysql)
#     recommended =  posts.getRecommendedPosts()
#     latest =  posts.getLatestPosts()
#     return render_template('blog/bloghome.html',tags = tags,recommended = recommended,latest = latest,user = user)


if __name__ == '__main__':
    # Print server startup information
    print("\n" + "="*60)
    print("🚀 Starting Flask Server with Database API Keys")
    print("="*60)
    print(f"📂 Database: {db.db_path}")
    print(f"🔐 Key loaded from database")
    print(f"🌐 Server: http://0.0.0.0:5000")
    print(f"📝 Test page: http://0.0.0.0:5000/test-api")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)