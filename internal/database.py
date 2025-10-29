import sqlite3
import os
import sys

class DatabaseManager:
    """SQLite database manager for API keys"""
    
    def __init__(self, db_path=None):
        """Initialize database connection"""
        if db_path is None:
            # Default to xC/internal/keys.db
            db_path = os.path.join(os.path.dirname(__file__), 'keys.db')
        
        self.db_path = db_path
        self.connection = None
        self._ensure_database()
    
    def _ensure_database(self):
        """Create database and tables if they don't exist"""
        try:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row  # Return rows as dictionaries
            
            # Create keys table if it doesn't exist
            cursor = self.connection.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_name TEXT NOT NULL UNIQUE,
                    key_value TEXT NOT NULL,
                    hw_fingerprint TEXT,
                    hw_components TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            
            self.connection.commit()
            print(f"✅ Database initialized at: {self.db_path}")
            
        except sqlite3.Error as e:
            print(f"❌ Database error: {e}")
            sys.exit(1)
    
    def get_api_key(self, key_name='main'):
        """Get API key from database"""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                'SELECT key_value FROM api_keys WHERE key_name = ? AND is_active = 1',
                (key_name,)
            )
            row = cursor.fetchone()
            
            if row:
                return row['key_value']
            return None
            
        except sqlite3.Error as e:
            print(f"❌ Error retrieving key: {e}")
            return None
    
    def set_api_key(self, key_value, key_name='main'):
        """Set API key in database"""
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO api_keys (key_name, key_value, is_active)
                VALUES (?, ?, 1)
                ON CONFLICT(key_name) 
                DO UPDATE SET 
                    key_value = excluded.key_value,
                    is_active = 1,
                    updated_at = CURRENT_TIMESTAMP
            ''', (key_name, key_value))
            
            self.connection.commit()
            return True
            
        except sqlite3.Error as e:
            print(f"❌ Error setting key: {e}")
            return False
    
    def delete_api_key(self, key_name='main'):
        """Delete (deactivate) API key"""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                'UPDATE api_keys SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE key_name = ?',
                (key_name,)
            )
            self.connection.commit()
            return True
            
        except sqlite3.Error as e:
            print(f"❌ Error deleting key: {e}")
            return False
    
    def list_keys(self):
        """List all active API keys"""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                'SELECT key_name, key_value, hw_fingerprint, created_at, updated_at FROM api_keys WHERE is_active = 1'
            )
            return cursor.fetchall()
            
        except sqlite3.Error as e:
            print(f"❌ Error listing keys: {e}")
            return []
    
    def get_hardware_for_key(self, api_key_value):
        """Get hardware binding for a specific API key"""
        try:
            cursor = self.connection.cursor()
            cursor.execute(
                'SELECT hw_fingerprint, hw_components FROM api_keys WHERE key_value = ? AND is_active = 1',
                (api_key_value,)
            )
            row = cursor.fetchone()
            
            if row:
                return {
                    'hw_fingerprint': row['hw_fingerprint'],
                    'hw_components': row['hw_components']
                }
            return None
            
        except sqlite3.Error as e:
            print(f"❌ Error retrieving hardware: {e}")
            return None
    
    def bind_hardware_to_key(self, api_key_value, hw_fingerprint=None, hw_components=None):
        """Bind hardware to a specific API key"""
        try:
            cursor = self.connection.cursor()
            
            # First check if API key exists
            cursor.execute(
                'SELECT key_name FROM api_keys WHERE key_value = ? AND is_active = 1',
                (api_key_value,)
            )
            row = cursor.fetchone()
            
            if not row:
                print(f"❌ API key not found: {api_key_value}")
                return False
            
            # Update hardware binding
            cursor.execute('''
                UPDATE api_keys 
                SET hw_fingerprint = ?, hw_components = ?, updated_at = CURRENT_TIMESTAMP
                WHERE key_value = ? AND is_active = 1
            ''', (hw_fingerprint, hw_components, api_key_value))
            
            self.connection.commit()
            return True
            
        except sqlite3.Error as e:
            print(f"❌ Error binding hardware: {e}")
            return False
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None


# Global instance
db = DatabaseManager()

