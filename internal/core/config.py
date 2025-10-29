import os

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    ENV = 'development'
    
class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    ENV = 'production'
    SESSION_COOKIE_SECURE = True
    
class TestingConfig(Config):
    """Testing configuration."""
    DEBUG = True
    TESTING = True
    ENV = 'testing'
