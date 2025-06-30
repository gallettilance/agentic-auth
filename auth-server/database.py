#!/usr/bin/env python3
"""
Database layer for production-grade authentication system
Handles roles, permissions, clients, and secure configuration
"""

import sqlite3
import hashlib
import secrets
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path

logger = logging.getLogger(__name__)

class RoleType(str, Enum):
    ADMIN = "admin"
    USER = "user"
    DEVELOPER = "developer"
    MANAGER = "manager"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Role:
    id: int
    name: str
    description: str
    is_default: bool
    created_at: datetime
    updated_at: datetime

@dataclass
class Permission:
    id: int
    scope: str
    description: str
    risk_level: RiskLevel
    requires_admin: bool
    created_at: datetime
    updated_at: datetime

@dataclass
class User:
    id: int
    email: str
    is_active: bool
    is_admin: bool
    created_at: datetime
    updated_at: datetime
    roles: List[str]

@dataclass
class Client:
    id: int
    client_id: str
    client_secret_hash: str
    client_type: str
    description: str
    token_exchange_enabled: bool
    allowed_audiences: List[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

class AuthDatabase:
    """Production-grade authentication database"""
    
    def __init__(self, db_path: str = "auth.db"):
        self.db_path = db_path
        self.init_database()
        
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection with proper configuration"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
        
    def init_database(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            # Create tables
            conn.executescript("""
                -- Roles table
                CREATE TABLE IF NOT EXISTS roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT NOT NULL,
                    is_default BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Permissions/Scopes table
                CREATE TABLE IF NOT EXISTS permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT UNIQUE NOT NULL,
                    description TEXT NOT NULL,
                    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
                    requires_admin BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Role-Permission mapping
                CREATE TABLE IF NOT EXISTS role_permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    role_id INTEGER NOT NULL,
                    permission_id INTEGER NOT NULL,
                    auto_approve BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
                    FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE,
                    UNIQUE (role_id, permission_id)
                );
                
                -- Users table
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    is_admin BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                -- User-Role mapping
                CREATE TABLE IF NOT EXISTS user_roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    role_id INTEGER NOT NULL,
                    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    assigned_by TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
                    UNIQUE (user_id, role_id)
                );
                
                -- OAuth clients table
                CREATE TABLE IF NOT EXISTS oauth_clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT UNIQUE NOT NULL,
                    client_secret_hash TEXT NOT NULL,
                    client_type TEXT NOT NULL CHECK (client_type IN ('confidential', 'public')),
                    description TEXT,
                    token_exchange_enabled BOOLEAN DEFAULT FALSE,
                    allowed_audiences TEXT, -- JSON array
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Configuration table for secure settings
                CREATE TABLE IF NOT EXISTS configuration (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    is_encrypted BOOLEAN DEFAULT FALSE,
                    description TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Approval requests table
                CREATE TABLE IF NOT EXISTS approval_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT UNIQUE NOT NULL,
                    user_email TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    required_scope TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    justification TEXT,
                    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
                    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    approved_by TEXT,
                    approved_at TIMESTAMP,
                    denied_by TEXT,
                    denied_at TIMESTAMP,
                    denial_reason TEXT,
                    metadata TEXT, -- JSON
                    FOREIGN KEY (user_email) REFERENCES users (email)
                );
                
                -- Scope policies table for configurable approval rules
                CREATE TABLE IF NOT EXISTS scope_policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope TEXT NOT NULL,
                    policy_type TEXT NOT NULL CHECK (policy_type IN ('auto_approve', 'admin_required', 'role_required', 'always_deny')),
                    target_roles TEXT, -- JSON array of roles this policy applies to
                    conditions TEXT, -- JSON conditions for policy evaluation
                    description TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                -- User scope limits table for maximum allowed scopes
                CREATE TABLE IF NOT EXISTS user_scope_limits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_email TEXT,
                    role_name TEXT,
                    max_scopes TEXT, -- JSON array of maximum allowed scopes
                    auto_approve_scopes TEXT, -- JSON array of auto-approved scopes  
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_email) REFERENCES users (email),
                    FOREIGN KEY (role_name) REFERENCES roles (name)
                );
                
                -- Create indexes for performance
                CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
                CREATE INDEX IF NOT EXISTS idx_users_active ON users (is_active);
                CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests (status);
                CREATE INDEX IF NOT EXISTS idx_approval_requests_user ON approval_requests (user_email);
                CREATE INDEX IF NOT EXISTS idx_oauth_clients_active ON oauth_clients (is_active);
                CREATE INDEX IF NOT EXISTS idx_configuration_key ON configuration (key);
                CREATE INDEX IF NOT EXISTS idx_scope_policies_scope ON scope_policies (scope);
                CREATE INDEX IF NOT EXISTS idx_scope_policies_active ON scope_policies (is_active);
                CREATE INDEX IF NOT EXISTS idx_user_scope_limits_email ON user_scope_limits (user_email);
                CREATE INDEX IF NOT EXISTS idx_user_scope_limits_role ON user_scope_limits (role_name);
            """)
            
            # Initialize default data
            self._init_default_data(conn)
            
    def _init_default_data(self, conn: sqlite3.Connection):
        """Initialize default roles, permissions, and configuration"""
        
        # Check if already initialized
        if conn.execute("SELECT COUNT(*) FROM roles").fetchone()[0] > 0:
            return
            
        logger.info("Initializing default authentication data...")
        
        # Create only admin and user roles (simplified)
        default_roles = [
            ("admin", "System administrator with full access", False),
            ("user", "Standard user with basic permissions", True)
        ]
        
        for name, description, is_default in default_roles:
            conn.execute(
                "INSERT INTO roles (name, description, is_default) VALUES (?, ?, ?)",
                (name, description, is_default)
            )
            
        # Create essential permissions only
        default_permissions = [
            ("read:files", "Read file system information", "low", False),
            ("execute:commands", "Execute system commands", "critical", True),
            ("admin:users", "Manage user accounts and permissions", "critical", True),
            ("admin:roles", "Manage roles and permissions", "critical", True),
            ("admin:clients", "Manage OAuth clients", "critical", True),
            ("admin:config", "Manage system configuration", "critical", True)
        ]
        
        for scope, description, risk_level, requires_admin in default_permissions:
            conn.execute(
                "INSERT INTO permissions (scope, description, risk_level, requires_admin) VALUES (?, ?, ?, ?)",
                (scope, description, risk_level, requires_admin)
            )
            
        # Set up role-permission mappings (simplified)
        role_permissions = {
            "admin": [
                ("read:files", True),
                ("execute:commands", True),
                ("admin:users", True),
                ("admin:roles", True),
                ("admin:clients", True),
                ("admin:config", True)
            ],
            "user": [
                # RFC 8693 Token Exchange Protocol:
                # Users start with NO permissions in their initial token (empty scope)
                # They must use token exchange to request specific permission scopes
                # This provides better security and audit trail
                # Available scopes: read:files (auto-approve), execute:commands (requires admin approval)
            ]
        }
        
        for role_name, permissions in role_permissions.items():
            role_id = conn.execute("SELECT id FROM roles WHERE name = ?", (role_name,)).fetchone()[0]
            
            for scope, auto_approve in permissions:
                perm_id = conn.execute("SELECT id FROM permissions WHERE scope = ?", (scope,)).fetchone()[0]
                conn.execute(
                    "INSERT INTO role_permissions (role_id, permission_id, auto_approve) VALUES (?, ?, ?)",
                    (role_id, perm_id, auto_approve)
                )
                
        # Create default OAuth clients
        default_clients = [
            ("mcp-server", "MCP Server for tool execution", "confidential", True, ["file-service", "command-executor", "mcp-tools"]),
            ("chat-app", "Chat application frontend", "confidential", True, ["mcp-server"])
        ]
        
        for client_id, description, client_type, token_exchange, audiences in default_clients:
            client_secret = secrets.token_urlsafe(32)
            client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
            
            conn.execute(
                """INSERT INTO oauth_clients 
                   (client_id, client_secret_hash, client_type, description, token_exchange_enabled, allowed_audiences) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (client_id, client_secret_hash, client_type, description, token_exchange, json.dumps(audiences))
            )
            
            # Store the plaintext secret in configuration (encrypted in production)
            conn.execute(
                "INSERT INTO configuration (key, value, description) VALUES (?, ?, ?)",
                (f"client_secret_{client_id}", client_secret, f"Client secret for {client_id}")
            )
        
        # Create default scope policies (RFC 8693 compliant)
        default_scope_policies = [
            # Basic read access - auto-approve for all users
            ("read:files", "auto_approve", ["user", "admin"], 
             {"description": "Basic file system read access", "max_risk": "low"}, 
             "Auto-approve basic read access for all authenticated users"),
            
            # Command execution - requires admin approval for regular users, auto for admins
            ("execute:commands", "role_required", ["admin"], 
             {"description": "System command execution", "max_risk": "critical", "fallback": "admin_required"}, 
             "Auto-approve for admins, require admin approval for others"),
            
            # Admin scopes - always require admin role
            ("admin:users", "role_required", ["admin"], 
             {"description": "User management", "max_risk": "critical"}, 
             "Requires admin role"),
            ("admin:roles", "role_required", ["admin"], 
             {"description": "Role management", "max_risk": "critical"}, 
             "Requires admin role"),
            ("admin:clients", "role_required", ["admin"], 
             {"description": "OAuth client management", "max_risk": "critical"}, 
             "Requires admin role"),
            ("admin:config", "role_required", ["admin"], 
             {"description": "System configuration", "max_risk": "critical"}, 
             "Requires admin role")
        ]
        
        for scope, policy_type, target_roles, conditions, description in default_scope_policies:
            conn.execute(
                """INSERT INTO scope_policies 
                   (scope, policy_type, target_roles, conditions, description) 
                   VALUES (?, ?, ?, ?, ?)""",
                (scope, policy_type, json.dumps(target_roles), json.dumps(conditions), description)
            )
        
        # Note: We rely purely on scope policies for approval decisions
        # No need for user scope limits - policies handle everything
            
        logger.info("Default authentication data initialized successfully")
        
    def create_admin_user(self, email: str, assigned_by: str = "system") -> bool:
        """Create an admin user with full permissions"""
        try:
            with self.get_connection() as conn:
                # Create user
                conn.execute(
                    "INSERT OR REPLACE INTO users (email, is_active, is_admin) VALUES (?, TRUE, TRUE)",
                    (email,)
                )
                
                user_id = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()[0]
                admin_role_id = conn.execute("SELECT id FROM roles WHERE name = 'admin'", ()).fetchone()[0]
                
                # Assign admin role
                conn.execute(
                    "INSERT OR REPLACE INTO user_roles (user_id, role_id, assigned_by) VALUES (?, ?, ?)",
                    (user_id, admin_role_id, assigned_by)
                )
                
                logger.info(f"Admin user created: {email}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to create admin user {email}: {e}")
            return False
            
    def get_user(self, email: str) -> Optional[User]:
        """Get user with roles"""
        with self.get_connection() as conn:
            user_row = conn.execute(
                "SELECT * FROM users WHERE email = ? AND is_active = TRUE",
                (email,)
            ).fetchone()
            
            if not user_row:
                return None
                
            # Get user roles
            roles = conn.execute("""
                SELECT r.name FROM roles r
                JOIN user_roles ur ON r.id = ur.role_id
                WHERE ur.user_id = ?
            """, (user_row['id'],)).fetchall()
            
            return User(
                id=user_row['id'],
                email=user_row['email'],
                is_active=user_row['is_active'],
                is_admin=user_row['is_admin'],
                created_at=datetime.fromisoformat(user_row['created_at']),
                updated_at=datetime.fromisoformat(user_row['updated_at']),
                roles=[role['name'] for role in roles]
            )
            
    def get_user_permissions(self, email: str) -> Dict[str, Dict[str, Any]]:
        """Get user permissions with auto-approval settings"""
        with self.get_connection() as conn:
            permissions = conn.execute("""
                SELECT p.scope, p.description, p.risk_level, p.requires_admin, rp.auto_approve
                FROM permissions p
                JOIN role_permissions rp ON p.id = rp.permission_id
                JOIN roles r ON rp.role_id = r.id
                JOIN user_roles ur ON r.id = ur.role_id
                JOIN users u ON ur.user_id = u.id
                WHERE u.email = ? AND u.is_active = TRUE
            """, (email,)).fetchall()
            
            result = {}
            for perm in permissions:
                scope = perm['scope']
                if scope not in result:
                    result[scope] = {
                        'description': perm['description'],
                        'risk_level': perm['risk_level'],
                        'requires_admin': bool(perm['requires_admin']),
                        'auto_approve': bool(perm['auto_approve'])
                    }
                else:
                    # If any role has auto_approve, set it to True
                    result[scope]['auto_approve'] = result[scope]['auto_approve'] or bool(perm['auto_approve'])
                    
            return result
            
    def validate_client_credentials(self, client_id: str, client_secret: str) -> bool:
        """Validate OAuth client credentials"""
        with self.get_connection() as conn:
            client_row = conn.execute(
                "SELECT client_secret_hash FROM oauth_clients WHERE client_id = ? AND is_active = TRUE",
                (client_id,)
            ).fetchone()
            
            if not client_row:
                return False
                
            client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
            return client_secret_hash == client_row['client_secret_hash']
            
    def get_client(self, client_id: str) -> Optional[Client]:
        """Get OAuth client information"""
        with self.get_connection() as conn:
            client_row = conn.execute(
                "SELECT * FROM oauth_clients WHERE client_id = ? AND is_active = TRUE",
                (client_id,)
            ).fetchone()
            
            if not client_row:
                return None
                
            return Client(
                id=client_row['id'],
                client_id=client_row['client_id'],
                client_secret_hash=client_row['client_secret_hash'],
                client_type=client_row['client_type'],
                description=client_row['description'],
                token_exchange_enabled=bool(client_row['token_exchange_enabled']),
                allowed_audiences=json.loads(client_row['allowed_audiences'] or '[]'),
                is_active=bool(client_row['is_active']),
                created_at=datetime.fromisoformat(client_row['created_at']),
                updated_at=datetime.fromisoformat(client_row['updated_at'])
            )
            
    def get_configuration(self, key: str) -> Optional[str]:
        """Get configuration value"""
        with self.get_connection() as conn:
            config_row = conn.execute(
                "SELECT value, is_encrypted FROM configuration WHERE key = ?",
                (key,)
            ).fetchone()
            
            if not config_row:
                return None
                
            value = config_row['value']
            if config_row['is_encrypted']:
                # TODO: Implement encryption/decryption
                pass
                
            return value
            
    def set_configuration(self, key: str, value: str, description: str = "", is_encrypted: bool = False):
        """Set configuration value"""
        if is_encrypted:
            # TODO: Implement encryption
            pass
            
        with self.get_connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO configuration (key, value, description, is_encrypted) 
                   VALUES (?, ?, ?, ?)""",
                (key, value, description, is_encrypted)
            )
            
    def create_user(self, email: str, roles: Optional[List[str]] = None, is_admin: bool = False) -> bool:
        """Create a new user with specified roles"""
        if roles is None:
            roles = ["user"]  # Default role
            
        try:
            with self.get_connection() as conn:
                # Create user
                conn.execute(
                    "INSERT OR REPLACE INTO users (email, is_active, is_admin) VALUES (?, TRUE, ?)",
                    (email, is_admin)
                )
                
                user_id = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()[0]
                
                # Assign roles
                for role_name in roles:
                    role_row = conn.execute("SELECT id FROM roles WHERE name = ?", (role_name,)).fetchone()
                    if role_row:
                        conn.execute(
                            "INSERT OR REPLACE INTO user_roles (user_id, role_id, assigned_by) VALUES (?, ?, ?)",
                            (user_id, role_row[0], "system")
                        )
                        
                logger.info(f"User created: {email} with roles: {roles}")
                logger.info(f"🔒 User {email} will start with empty scope per RFC 8693 token exchange protocol")
                return True
                
        except Exception as e:
            logger.error(f"Failed to create user {email}: {e}")
            return False
            
    def get_all_permissions(self) -> List[Permission]:
        """Get all available permissions"""
        with self.get_connection() as conn:
            permissions = conn.execute("SELECT * FROM permissions ORDER BY scope").fetchall()
            
            return [
                Permission(
                    id=perm['id'],
                    scope=perm['scope'],
                    description=perm['description'],
                    risk_level=RiskLevel(perm['risk_level']),
                    requires_admin=bool(perm['requires_admin']),
                    created_at=datetime.fromisoformat(perm['created_at']),
                    updated_at=datetime.fromisoformat(perm['updated_at'])
                )
                for perm in permissions
            ]
            
    def get_all_roles(self) -> List[Role]:
        """Get all available roles"""
        with self.get_connection() as conn:
            roles = conn.execute("SELECT * FROM roles ORDER BY name").fetchall()
            
            return [
                Role(
                    id=role['id'],
                    name=role['name'],
                    description=role['description'],
                    is_default=bool(role['is_default']),
                    created_at=datetime.fromisoformat(role['created_at']),
                    updated_at=datetime.fromisoformat(role['updated_at'])
                )
                for role in roles
            ]
    
    def get_scope_policy(self, scope: str, user_roles: List[str]) -> Optional[Dict[str, Any]]:
        """Get scope policy for a specific scope and user roles"""
        with self.get_connection() as conn:
            # Find the most specific policy that applies to the user's roles
            policies = conn.execute("""
                SELECT * FROM scope_policies 
                WHERE scope = ? AND is_active = TRUE
                ORDER BY id
            """, (scope,)).fetchall()
            
            for policy in policies:
                target_roles = json.loads(policy['target_roles'] or '[]')
                # Check if policy applies to any of the user's roles
                if not target_roles or any(role in target_roles for role in user_roles):
                    return {
                        'scope': policy['scope'],
                        'policy_type': policy['policy_type'],
                        'target_roles': target_roles,
                        'conditions': json.loads(policy['conditions'] or '{}'),
                        'description': policy['description']
                    }
            return None
    
    def get_user_scope_limits(self, user_email: str, user_roles: List[str]) -> Dict[str, Any]:
        """Get scope limits for a user based on their email and roles"""
        with self.get_connection() as conn:
            # First try to find user-specific limits
            user_limits = conn.execute("""
                SELECT * FROM user_scope_limits 
                WHERE user_email = ?
                ORDER BY created_at DESC
                LIMIT 1
            """, (user_email,)).fetchone()
            
            if user_limits:
                return {
                    'max_scopes': json.loads(user_limits['max_scopes'] or '[]'),
                    'auto_approve_scopes': json.loads(user_limits['auto_approve_scopes'] or '[]'),
                    'source': 'user_specific'
                }
            
            # Fall back to role-based limits (try each role, prioritize admin)
            for role in sorted(user_roles, key=lambda x: x == 'admin', reverse=True):
                role_limits = conn.execute("""
                    SELECT * FROM user_scope_limits 
                    WHERE user_email IS NULL AND role_name = ?
                    ORDER BY created_at DESC
                    LIMIT 1
                """, (role,)).fetchone()
                
                if role_limits:
                    return {
                        'max_scopes': json.loads(role_limits['max_scopes'] or '[]'),
                        'auto_approve_scopes': json.loads(role_limits['auto_approve_scopes'] or '[]'),
                        'source': f'role_{role}'
                    }
            
            # Default fallback
            return {
                'max_scopes': [],
                'auto_approve_scopes': [],
                'source': 'default'
            }
    
    def evaluate_scope_request(self, user_email: str, requested_scopes: List[str]) -> Dict[str, Any]:
        """Evaluate scope request using database policies (RFC 8693 compliant)"""
        user = self.get_user(user_email)
        if not user:
            return {"error": "User not found"}
        
        user_roles = user.roles
        
        auto_approved = []
        requires_approval = []
        denied = []
        
        for scope in requested_scopes:
            # Get policy for this scope
            policy = self.get_scope_policy(scope, user_roles)
            
            if not policy:
                # No specific policy - default to requiring admin approval
                requires_approval.append(scope)
                continue
            
            # Apply policy based on type
            if policy['policy_type'] == 'auto_approve':
                auto_approved.append(scope)
            elif policy['policy_type'] == 'role_required':
                target_roles = policy['target_roles']
                if any(role in target_roles for role in user_roles):
                    auto_approved.append(scope)
                else:
                    # Check for fallback policy
                    conditions = policy['conditions']
                    if conditions.get('fallback') == 'admin_required':
                        requires_approval.append(scope)
                    else:
                        denied.append({
                            'scope': scope,
                            'reason': f'Requires one of roles: {target_roles}',
                            'user_roles': user_roles
                        })
            elif policy['policy_type'] == 'admin_required':
                requires_approval.append(scope)
            elif policy['policy_type'] == 'always_deny':
                denied.append({
                    'scope': scope,
                    'reason': 'Scope is always denied by policy',
                    'policy': policy['description']
                })
        
        return {
            'auto_approved': auto_approved,
            'requires_approval': requires_approval,
            'denied': denied,
            'user_roles': user_roles
        }

# Global database instance
auth_db = AuthDatabase()

def init_admin_user(email: str) -> bool:
    """Initialize the first admin user"""
    return auth_db.create_admin_user(email, "initial_setup")

def get_client_secret(client_id: str) -> Optional[str]:
    """Get client secret from configuration"""
    return auth_db.get_configuration(f"client_secret_{client_id}") 