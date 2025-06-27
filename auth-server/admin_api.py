#!/usr/bin/env python3
"""
Admin API endpoints for production-grade authentication system
Provides comprehensive management of users, roles, permissions, and clients
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import secrets
import hashlib

from database import auth_db, User, Role, Permission, Client, RoleType, RiskLevel

# Admin API router
admin_router = APIRouter(prefix="/api/admin", tags=["admin"])

# Pydantic models for API
class CreateUserRequest(BaseModel):
    email: str
    roles: List[str] = ["user"]
    is_admin: bool = False

class UpdateUserRequest(BaseModel):
    roles: Optional[List[str]] = None
    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None

class CreateRoleRequest(BaseModel):
    name: str
    description: str
    permissions: List[str] = []

class CreatePermissionRequest(BaseModel):
    scope: str
    description: str
    risk_level: str
    requires_admin: bool = False

class CreateClientRequest(BaseModel):
    client_id: str
    description: str
    client_type: str = "confidential"
    token_exchange_enabled: bool = True
    allowed_audiences: List[str] = []

class AssignRoleRequest(BaseModel):
    user_email: str
    role_name: str

class RolePermissionRequest(BaseModel):
    role_name: str
    permission_scope: str
    auto_approve: bool = False

# Helper function to verify admin access
def verify_admin_access(user_email: str):
    """Verify user has admin access"""
    user = auth_db.get_user(user_email)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# User Management Endpoints
@admin_router.get("/users", response_model=List[Dict[str, Any]])
async def list_users(current_user_email: str = Depends(lambda: "admin@example.com")):  # TODO: Get from auth
    """List all users"""
    verify_admin_access(current_user_email)
    
    with auth_db.get_connection() as conn:
        users = conn.execute("""
            SELECT u.*, GROUP_CONCAT(r.name) as roles
            FROM users u
            LEFT JOIN user_roles ur ON u.id = ur.user_id
            LEFT JOIN roles r ON ur.role_id = r.id
            GROUP BY u.id
            ORDER BY u.email
        """).fetchall()
        
        return [
            {
                "id": user["id"],
                "email": user["email"],
                "is_active": bool(user["is_active"]),
                "is_admin": bool(user["is_admin"]),
                "roles": user["roles"].split(",") if user["roles"] else [],
                "created_at": user["created_at"],
                "updated_at": user["updated_at"]
            }
            for user in users
        ]

@admin_router.post("/users")
async def create_user(
    request: CreateUserRequest,
    current_user_email: str = Depends(lambda: "admin@example.com")
):
    """Create a new user"""
    verify_admin_access(current_user_email)
    
    if auth_db.create_user(request.email, request.roles, request.is_admin):
        return {"message": f"User {request.email} created successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to create user")

@admin_router.put("/users/{user_email}")
async def update_user(
    user_email: str,
    request: UpdateUserRequest,
    current_user_email: str = Depends(lambda: "admin@example.com")
):
    """Update user information"""
    verify_admin_access(current_user_email)
    
    try:
        with auth_db.get_connection() as conn:
            updates = []
            params = []
            
            if request.is_active is not None:
                updates.append("is_active = ?")
                params.append(request.is_active)
                
            if request.is_admin is not None:
                updates.append("is_admin = ?")
                params.append(request.is_admin)
                
            if updates:
                updates.append("updated_at = CURRENT_TIMESTAMP")
                params.append(user_email)
                
                conn.execute(
                    f"UPDATE users SET {', '.join(updates)} WHERE email = ?",
                    params
                )
            
            # Update roles if provided
            if request.roles is not None:
                user_id = conn.execute("SELECT id FROM users WHERE email = ?", (user_email,)).fetchone()[0]
                
                # Remove existing roles
                conn.execute("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
                
                # Add new roles
                for role_name in request.roles:
                    role_row = conn.execute("SELECT id FROM roles WHERE name = ?", (role_name,)).fetchone()
                    if role_row:
                        conn.execute(
                            "INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES (?, ?, ?)",
                            (user_id, role_row[0], current_user_email)
                        )
            
            return {"message": f"User {user_email} updated successfully"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to update user: {e}")

@admin_router.delete("/users/{user_email}")
async def delete_user(
    user_email: str,
    current_user_email: str = Depends(lambda: "admin@example.com")
):
    """Deactivate a user (soft delete)"""
    verify_admin_access(current_user_email)
    
    try:
        with auth_db.get_connection() as conn:
            conn.execute(
                "UPDATE users SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE email = ?",
                (user_email,)
            )
            return {"message": f"User {user_email} deactivated successfully"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to deactivate user: {e}")

# Role Management Endpoints
@admin_router.get("/roles")
async def list_roles(current_user_email: str = Depends(lambda: "admin@example.com")):
    """List all roles with their permissions"""
    verify_admin_access(current_user_email)
    
    with auth_db.get_connection() as conn:
        roles = conn.execute("""
            SELECT r.*, GROUP_CONCAT(p.scope) as permissions
            FROM roles r
            LEFT JOIN role_permissions rp ON r.id = rp.role_id
            LEFT JOIN permissions p ON rp.permission_id = p.id
            GROUP BY r.id
            ORDER BY r.name
        """).fetchall()
        
        return [
            {
                "id": role["id"],
                "name": role["name"],
                "description": role["description"],
                "is_default": bool(role["is_default"]),
                "permissions": role["permissions"].split(",") if role["permissions"] else [],
                "created_at": role["created_at"],
                "updated_at": role["updated_at"]
            }
            for role in roles
        ]

@admin_router.post("/roles")
async def create_role(
    request: CreateRoleRequest,
    current_user_email: str = Depends(lambda: "admin@example.com")
):
    """Create a new role"""
    verify_admin_access(current_user_email)
    
    try:
        with auth_db.get_connection() as conn:
            # Create role
            conn.execute(
                "INSERT INTO roles (name, description) VALUES (?, ?)",
                (request.name, request.description)
            )
            
            role_id = conn.execute("SELECT id FROM roles WHERE name = ?", (request.name,)).fetchone()[0]
            
            # Assign permissions
            for permission_scope in request.permissions:
                perm_row = conn.execute("SELECT id FROM permissions WHERE scope = ?", (permission_scope,)).fetchone()
                if perm_row:
                    conn.execute(
                        "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
                        (role_id, perm_row[0])
                    )
            
            return {"message": f"Role {request.name} created successfully"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create role: {e}")

@admin_router.delete("/roles/{role_name}")
async def delete_role(
    role_name: str,
    current_user_email: str = Depends(lambda: "admin@example.com")
):
    """Delete a role"""
    verify_admin_access(current_user_email)
    
    if role_name in ["admin", "user"]:
        raise HTTPException(status_code=400, detail="Cannot delete system roles")
    
    try:
        with auth_db.get_connection() as conn:
            conn.execute("DELETE FROM roles WHERE name = ?", (role_name,))
            return {"message": f"Role {role_name} deleted successfully"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to delete role: {e}")

# Permission Management Endpoints
@admin_router.get("/permissions")
async def list_permissions(current_user_email: str = Depends(lambda: "admin@example.com")):
    """List all permissions"""
    verify_admin_access(current_user_email)
    
    permissions = auth_db.get_all_permissions()
    return [
        {
            "id": perm.id,
            "scope": perm.scope,
            "description": perm.description,
            "risk_level": perm.risk_level.value,
            "requires_admin": perm.requires_admin,
            "created_at": perm.created_at.isoformat(),
            "updated_at": perm.updated_at.isoformat()
        }
        for perm in permissions
    ]

@admin_router.post("/permissions")
async def create_permission(
    request: CreatePermissionRequest,
    current_user_email: str = Depends(lambda: "admin@example.com")
):
    """Create a new permission"""
    verify_admin_access(current_user_email)
    
    try:
        with auth_db.get_connection() as conn:
            conn.execute(
                "INSERT INTO permissions (scope, description, risk_level, requires_admin) VALUES (?, ?, ?, ?)",
                (request.scope, request.description, request.risk_level, request.requires_admin)
            )
            return {"message": f"Permission {request.scope} created successfully"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create permission: {e}")

@admin_router.delete("/permissions/{scope}")
async def delete_permission(
    scope: str,
    current_user_email: str = Depends(lambda: "admin@example.com")
):
    """Delete a permission"""
    verify_admin_access(current_user_email)
    
    # Protect system permissions
    system_permissions = ["read:files", "execute:commands", "admin:users", "admin:roles", "admin:clients"]
    if scope in system_permissions:
        raise HTTPException(status_code=400, detail="Cannot delete system permissions")
    
    try:
        with auth_db.get_connection() as conn:
            conn.execute("DELETE FROM permissions WHERE scope = ?", (scope,))
            return {"message": f"Permission {scope} deleted successfully"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to delete permission: {e}")

# Role-Permission Management
@admin_router.post("/roles/permissions")
async def assign_permission_to_role(
    request: RolePermissionRequest,
    current_user_email: str = Depends(lambda: "admin@example.com")
):
    """Assign permission to role"""
    verify_admin_access(current_user_email)
    
    try:
        with auth_db.get_connection() as conn:
            role_row = conn.execute("SELECT id FROM roles WHERE name = ?", (request.role_name,)).fetchone()
            perm_row = conn.execute("SELECT id FROM permissions WHERE scope = ?", (request.permission_scope,)).fetchone()
            
            if not role_row or not perm_row:
                raise HTTPException(status_code=404, detail="Role or permission not found")
            
            conn.execute(
                "INSERT OR REPLACE INTO role_permissions (role_id, permission_id, auto_approve) VALUES (?, ?, ?)",
                (role_row[0], perm_row[0], request.auto_approve)
            )
            
            return {"message": f"Permission {request.permission_scope} assigned to role {request.role_name}"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to assign permission: {e}")

@admin_router.delete("/roles/{role_name}/permissions/{scope}")
async def remove_permission_from_role(
    role_name: str,
    scope: str,
    current_user_email: str = Depends(lambda: "admin@example.com")
):
    """Remove permission from role"""
    verify_admin_access(current_user_email)
    
    try:
        with auth_db.get_connection() as conn:
            conn.execute("""
                DELETE FROM role_permissions 
                WHERE role_id = (SELECT id FROM roles WHERE name = ?) 
                AND permission_id = (SELECT id FROM permissions WHERE scope = ?)
            """, (role_name, scope))
            
            return {"message": f"Permission {scope} removed from role {role_name}"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to remove permission: {e}")

# OAuth Client Management
@admin_router.get("/clients")
async def list_clients(current_user_email: str = Depends(lambda: "admin@example.com")):
    """List all OAuth clients"""
    verify_admin_access(current_user_email)
    
    with auth_db.get_connection() as conn:
        clients = conn.execute("SELECT * FROM oauth_clients ORDER BY client_id").fetchall()
        
        return [
            {
                "id": client["id"],
                "client_id": client["client_id"],
                "client_type": client["client_type"],
                "description": client["description"],
                "token_exchange_enabled": bool(client["token_exchange_enabled"]),
                "allowed_audiences": client["allowed_audiences"],
                "is_active": bool(client["is_active"]),
                "created_at": client["created_at"],
                "updated_at": client["updated_at"]
            }
            for client in clients
        ]

@admin_router.post("/clients")
async def create_client(
    request: CreateClientRequest,
    current_user_email: str = Depends(lambda: "admin@example.com")
):
    """Create a new OAuth client"""
    verify_admin_access(current_user_email)
    
    try:
        client_secret = secrets.token_urlsafe(32)
        client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
        
        with auth_db.get_connection() as conn:
            conn.execute(
                """INSERT INTO oauth_clients 
                   (client_id, client_secret_hash, client_type, description, token_exchange_enabled, allowed_audiences) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (request.client_id, client_secret_hash, request.client_type, 
                 request.description, request.token_exchange_enabled, str(request.allowed_audiences))
            )
            
            # Store client secret in configuration
            auth_db.set_configuration(
                f"client_secret_{request.client_id}",
                client_secret,
                f"Client secret for {request.client_id}"
            )
            
            return {
                "message": f"Client {request.client_id} created successfully",
                "client_secret": client_secret  # Return once for initial setup
            }
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create client: {e}")

@admin_router.delete("/clients/{client_id}")
async def delete_client(
    client_id: str,
    current_user_email: str = Depends(lambda: "admin@example.com")
):
    """Deactivate an OAuth client"""
    verify_admin_access(current_user_email)
    
    # Protect system clients
    if client_id in ["mcp-server", "chat-app"]:
        raise HTTPException(status_code=400, detail="Cannot delete system clients")
    
    try:
        with auth_db.get_connection() as conn:
            conn.execute(
                "UPDATE oauth_clients SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE client_id = ?",
                (client_id,)
            )
            return {"message": f"Client {client_id} deactivated successfully"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to deactivate client: {e}")

# System Statistics
@admin_router.get("/stats")
async def get_system_stats(current_user_email: str = Depends(lambda: "admin@example.com")):
    """Get system statistics"""
    verify_admin_access(current_user_email)
    
    with auth_db.get_connection() as conn:
        stats = {
            "users": {
                "total": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                "active": conn.execute("SELECT COUNT(*) FROM users WHERE is_active = TRUE").fetchone()[0],
                "admins": conn.execute("SELECT COUNT(*) FROM users WHERE is_admin = TRUE").fetchone()[0]
            },
            "roles": {
                "total": conn.execute("SELECT COUNT(*) FROM roles").fetchone()[0]
            },
            "permissions": {
                "total": conn.execute("SELECT COUNT(*) FROM permissions").fetchone()[0],
                "by_risk_level": {}
            },
            "clients": {
                "total": conn.execute("SELECT COUNT(*) FROM oauth_clients").fetchone()[0],
                "active": conn.execute("SELECT COUNT(*) FROM oauth_clients WHERE is_active = TRUE").fetchone()[0]
            }
        }
        
        # Get permission breakdown by risk level
        risk_levels = conn.execute("SELECT risk_level, COUNT(*) FROM permissions GROUP BY risk_level").fetchall()
        for risk_level, count in risk_levels:
            stats["permissions"]["by_risk_level"][risk_level] = count
        
        return stats 