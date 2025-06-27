#!/usr/bin/env python3
"""
Admin initialization script for production-grade authentication system
Allows setting up the first admin user and basic configuration
"""

import argparse
import sys
import os
import getpass
from pathlib import Path

# Add the auth-server directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from database import auth_db, init_admin_user

def main():
    parser = argparse.ArgumentParser(description="Initialize admin user for authentication system")
    parser.add_argument("--email", required=True, help="Admin user email address")
    parser.add_argument("--db-path", default="auth.db", help="Database file path (default: auth.db)")
    parser.add_argument("--force", action="store_true", help="Force recreate admin user if exists")
    
    args = parser.parse_args()
    
    # Set database path
    auth_db.db_path = args.db_path
    auth_db.init_database()
    
    print(f"🔧 Initializing authentication system...")
    print(f"📧 Admin email: {args.email}")
    print(f"🗄️  Database: {args.db_path}")
    
    # Check if user already exists
    existing_user = auth_db.get_user(args.email)
    if existing_user and not args.force:
        if existing_user.is_admin:
            print(f"✅ Admin user {args.email} already exists")
            return
        else:
            print(f"❌ User {args.email} exists but is not an admin")
            print("Use --force to upgrade to admin or choose a different email")
            return
    
    # Create admin user
    if init_admin_user(args.email):
        print(f"✅ Admin user {args.email} created successfully")
        
        # Show client credentials
        print("\n🔑 OAuth Client Credentials:")
        print("=" * 50)
        
        mcp_secret = auth_db.get_configuration("client_secret_mcp-server")
        chat_secret = auth_db.get_configuration("client_secret_chat-app")
        
        print(f"MCP Server:")
        print(f"  Client ID: mcp-server")
        print(f"  Client Secret: {mcp_secret}")
        print()
        print(f"Chat App:")
        print(f"  Client ID: chat-app") 
        print(f"  Client Secret: {chat_secret}")
        print()
        
        # Show environment variables
        print("🌍 Environment Variables:")
        print("=" * 50)
        print("Add these to your .env file or environment:")
        print()
        print(f"# Admin user")
        print(f"ADMIN_EMAIL={args.email}")
        print()
        print(f"# OAuth client secrets")
        print(f"MCP_CLIENT_SECRET={mcp_secret}")
        print(f"CHAT_CLIENT_SECRET={chat_secret}")
        print()
        print(f"# Database")
        print(f"AUTH_DB_PATH={args.db_path}")
        print()
        
        # Show user permissions
        permissions = auth_db.get_user_permissions(args.email)
        print("🔐 Admin Permissions:")
        print("=" * 50)
        for scope, details in permissions.items():
            auto = "✅ Auto-approve" if details['auto_approve'] else "❌ Requires approval"
            risk = details['risk_level'].upper()
            print(f"  {scope:<20} [{risk:>8}] {auto}")
        
        print("\n🚀 Authentication system ready!")
        print(f"   Start the auth server: python unified_auth_server.py")
        print(f"   Admin dashboard: http://localhost:8002/dashboard")
        
    else:
        print(f"❌ Failed to create admin user {args.email}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 