#!/usr/bin/env python3
"""
Setup Kubernetes users to match Keycloak users with RBAC permissions
"""

import os
import subprocess
import json
import requests
from typing import List, Dict, Optional

# Configuration
KEYCLOAK_URL = os.getenv("KEYCLOAK_ENV", "http://localhost:8002")
KEYCLOAK_REALM_NAME = os.getenv("KEYCLOAK_REALM_NAME", "authentication-demo")
KUBECONFIG = os.getenv("KUBECONFIG")

# User definitions matching Keycloak
USER_DEFINITIONS = [
    {
        "username": "lance",
        "email": "lance@example.com",
        "first_name": "Lance",
        "last_name": "User",
        "roles": ["user"]
    },
    {
        "username": "admin-user",
        "email": "admin@example.com", 
        "first_name": "Admin",
        "last_name": "User",
        "roles": ["admin"]
    }
]

class KubernetesUserSetup:
    """Setup Kubernetes users with RBAC permissions"""
    
    def __init__(self):
        self.keycloak_admin_token = None
        self.keycloak_headers = {}
        self.kubectl_path = None
        
    def check_prerequisites(self) -> bool:
        """Check if kubectl and KUBECONFIG are available"""
        print("🔍 Checking prerequisites...")
        
        if not KUBECONFIG:
            print("❌ KUBECONFIG environment variable not set")
            print("   Please set KUBECONFIG to point to your cluster config")
            return False
        
        if not os.path.exists(KUBECONFIG):
            print(f"❌ KUBECONFIG file not found: {KUBECONFIG}")
            return False
        
        # Find kubectl in common locations
        kubectl_paths = [
            "kubectl",  # In PATH
            "/opt/homebrew/bin/kubectl",  # Homebrew
            "/usr/local/bin/kubectl",  # Docker Desktop
            "/usr/bin/kubectl"  # System
        ]
        
        kubectl_path = None
        for path in kubectl_paths:
            try:
                if os.path.exists(path) or subprocess.run([path, "--version"], capture_output=True).returncode == 0:
                    kubectl_path = path
                    break
            except:
                continue
        
        if not kubectl_path:
            print("❌ kubectl not found in common locations")
            print("   Please install kubectl or add it to your PATH")
            return False
        
        self.kubectl_path = kubectl_path
        print(f"✅ Found kubectl at: {kubectl_path}")
        
        # Test kubectl access
        try:
            env = {"KUBECONFIG": KUBECONFIG} if KUBECONFIG else {}
            result = subprocess.run(
                [kubectl_path, "cluster-info"],
                capture_output=True,
                text=True,
                env=env
            )
            if result.returncode == 0:
                print("✅ kubectl access confirmed")
                return True
            else:
                print(f"❌ kubectl access failed: {result.stderr}")
                return False
        except Exception as e:
            print(f"❌ kubectl not available: {e}")
            return False
    
    def get_keycloak_admin_token(self) -> bool:
        """Get Keycloak admin token"""
        print("🔑 Getting Keycloak admin token...")
        
        try:
            response = requests.post(
                f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
                data={
                    'grant_type': 'password',
                    'client_id': 'admin-cli',
                    'username': 'admin',
                    'password': 'admin123'
                }
            )
            
            if response.status_code == 200:
                self.keycloak_admin_token = response.json()['access_token']
                self.keycloak_headers = {
                    'Authorization': f'Bearer {self.keycloak_admin_token}',
                    'Content-Type': 'application/json'
                }
                print("✅ Keycloak admin authentication successful")
                return True
            else:
                print(f"❌ Failed to get Keycloak admin token: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error getting Keycloak admin token: {e}")
            return False
    
    def get_keycloak_users(self) -> List[Dict]:
        """Get users from Keycloak"""
        print("👥 Getting users from Keycloak...")
        
        try:
            response = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/users",
                headers=self.keycloak_headers
            )
            
            if response.status_code == 200:
                users = response.json()
                print(f"✅ Found {len(users)} users in Keycloak")
                return users
            else:
                print(f"❌ Failed to get Keycloak users: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"❌ Error getting Keycloak users: {e}")
            return []
    
    def cleanup_existing_user_resources(self, username: str) -> None:
        """Clean up any existing resources for a user"""
        print(f"🧹 Cleaning up existing resources for {username}...")
        
        if not self.kubectl_path:
            return
        
        env = {"KUBECONFIG": KUBECONFIG} if KUBECONFIG else {}
        
        # Resources to clean up (both ServiceAccount and User-based resources)
        resources = [
            f"serviceaccount/{username}",
            f"secret/{username}-token",
            f"role/{username}-user",
            f"rolebinding/{username}-user",
            f"clusterrole/{username}-restricted",
            f"clusterrolebinding/{username}-restricted",
            f"clusterrolebinding/{username}-admin"
        ]
        
        for resource in resources:
            try:
                result = subprocess.run(
                    [self.kubectl_path, "delete", resource, "-n", "default", "--ignore-not-found=true"],
                    capture_output=True,
                    text=True,
                    env=env
                )
                if result.returncode == 0:
                    print(f"   ✅ Cleaned up {resource}")
            except Exception as e:
                print(f"   ⚠️ Could not clean up {resource}: {e}")
        
        # Also clean up any cluster-wide resources
        cluster_resources = [
            f"clusterrole/{username}-restricted",
            f"clusterrolebinding/{username}-restricted",
            f"clusterrolebinding/{username}-admin"
        ]
        
        for resource in cluster_resources:
            try:
                result = subprocess.run(
                    [self.kubectl_path, "delete", resource, "--ignore-not-found=true"],
                    capture_output=True,
                    text=True,
                    env=env
                )
                if result.returncode == 0:
                    print(f"   ✅ Cleaned up {resource}")
            except Exception as e:
                print(f"   ⚠️ Could not clean up {resource}: {e}")

    def create_k8s_user(self, username: str, email: str, roles: List[str]) -> bool:
        """Create Kubernetes user with RBAC permissions for OpenShift cluster"""
        print(f"🔄 Creating Kubernetes user: {username}")
        
        # First, clean up any existing resources for this user
        self.cleanup_existing_user_resources(username)
        
        # For OpenShift, we'll use a different approach - create a user directly
        # instead of relying on ServiceAccounts which might inherit cluster-admin
        if "admin" in roles:
            # Admin role - create cluster-admin binding
            rbac_yaml = f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {username}-admin
subjects:
- kind: User
  name: {username}
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
"""
        else:
            # User role - create namespace-specific role only
            rbac_yaml = f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {username}-user
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {username}-user
  namespace: default
subjects:
- kind: User
  name: {username}
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: {username}-user
  apiGroup: rbac.authorization.k8s.io
"""
        
        # Apply RBAC
        try:
            if not self.kubectl_path:
                print("❌ kubectl path not set")
                return False
            env = {"KUBECONFIG": KUBECONFIG} if KUBECONFIG else {}
            result = subprocess.run(
                [self.kubectl_path, "apply", "-f", "-"],
                input=rbac_yaml,
                capture_output=True,
                text=True,
                env=env
            )
            
            if result.returncode == 0:
                print(f"✅ Created RBAC for {username}")
                return True
            else:
                print(f"❌ RBAC creation failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ RBAC creation error: {e}")
            return False
    
    def get_service_account_token(self, username: str) -> Optional[str]:
        """Get the token for a user (for testing purposes)"""
        try:
            if not self.kubectl_path:
                print("❌ kubectl path not set")
                return None
            
            # For testing, we'll use the current admin token since we're testing user permissions
            # In a real scenario, the user would authenticate with their own credentials
            env = {"KUBECONFIG": KUBECONFIG} if KUBECONFIG else {}
            
            # Get the current token from kubeconfig for testing
            result = subprocess.run(
                [self.kubectl_path, "config", "view", "--minify", "-o", "jsonpath={.users[0].user.token}"],
                capture_output=True,
                text=True,
                env=env
            )
            
            if result.returncode == 0 and result.stdout:
                return result.stdout.strip()
            else:
                print(f"⚠️ Could not get admin token for testing {username}")
                return None
                
        except Exception as e:
            print(f"❌ Error getting token for {username}: {e}")
            return None
    
    def test_user_access(self, username: str, roles: List[str]) -> bool:
        """Test user access to verify RBAC is working with comprehensive tests"""
        print(f"🧪 Testing access for {username}...")
        
        # For testing, we'll use kubectl with user impersonation to test the RBAC
        if not self.kubectl_path:
            print("❌ kubectl path not set")
            return False
        
        env = {"KUBECONFIG": KUBECONFIG} if KUBECONFIG else {}
        
        # Comprehensive tests based on role using user impersonation
        if "admin" in roles:
            # Admin role tests
            tests = [
                ("cluster-wide nodes access", [self.kubectl_path, "get", "nodes", "--as", username]),
                ("cluster-wide namespaces access", [self.kubectl_path, "get", "namespaces", "--as", username]),
                ("default namespace pods access", [self.kubectl_path, "get", "pods", "-n", "default", "--as", username]),
                ("kube-system namespace pods access", [self.kubectl_path, "get", "pods", "-n", "kube-system", "--as", username])
            ]
        else:
            # User role tests - should only have default namespace access
            tests = [
                ("default namespace pods access (should succeed)", [self.kubectl_path, "get", "pods", "-n", "default", "--as", username]),
                ("default namespace services access (should succeed)", [self.kubectl_path, "get", "services", "-n", "default", "--as", username]),
                ("kube-system namespace pods access (should fail)", [self.kubectl_path, "get", "pods", "-n", "kube-system", "--as", username]),
                ("cluster-wide nodes access (should fail)", [self.kubectl_path, "get", "nodes", "--as", username]),
                ("cluster-wide namespaces access (should fail)", [self.kubectl_path, "get", "namespaces", "--as", username])
            ]
        
        passed_tests = 0
        total_tests = len(tests)
        
        for test_name, test_cmd in tests:
            try:
                result = subprocess.run(
                    test_cmd,
                    capture_output=True,
                    text=True,
                    env=env
                )
                
                if result.returncode == 0:
                    if "should fail" in test_name:
                        print(f"❌ {test_name} - UNEXPECTED SUCCESS (should have failed)")
                    else:
                        print(f"✅ {test_name} - SUCCESS")
                        passed_tests += 1
                else:
                    if "should fail" in test_name:
                        print(f"✅ {test_name} - CORRECTLY FAILED")
                        passed_tests += 1
                    else:
                        print(f"❌ {test_name} - FAILED: {result.stderr}")
                        
            except Exception as e:
                print(f"❌ {test_name} - ERROR: {e}")
        
        print(f"📊 Test Results for {username}: {passed_tests}/{total_tests} tests passed")
        
        if "admin" in roles:
            # Admin should pass all tests
            success = passed_tests == total_tests
        else:
            # User should pass default namespace tests and fail cluster-wide tests
            expected_passes = 2  # default namespace tests
            expected_fails = 3   # cluster-wide and kube-system tests
            success = passed_tests == expected_passes + expected_fails
        
        if success:
            print(f"✅ {username} RBAC configuration is correct")
        else:
            print(f"❌ {username} RBAC configuration has issues")
        
        return success
    
    def run_complete_setup(self) -> bool:
        """Run the complete Kubernetes user setup"""
        print("🚀 Kubernetes User Setup")
        print("=" * 40)
        
        # Check prerequisites
        if not self.check_prerequisites():
            return False
        
        # Get Keycloak admin token
        if not self.get_keycloak_admin_token():
            return False
        
        # Get Keycloak users
        keycloak_users = self.get_keycloak_users()
        if not keycloak_users:
            print("⚠️ No users found in Keycloak, using default definitions")
            keycloak_users = USER_DEFINITIONS
        
        # Create Kubernetes users
        success_count = 0
        for user in keycloak_users:
            username = user.get('username', user.get('email', '').split('@')[0])
            email = user.get('email', '')
            
            # Determine roles (simplified - you might want to get actual roles from Keycloak)
            if 'admin' in username.lower() or 'admin' in email.lower():
                roles = ['admin']
            else:
                roles = ['user']
            
            if self.create_k8s_user(username, email, roles):
                success_count += 1
        
        print(f"\n📊 Setup Summary:")
        print(f"   - Created {success_count} Kubernetes users")
        print(f"   - User role: default namespace access only")
        print(f"   - Admin role: cluster-wide access")
        
        # Test access
        print(f"\n🧪 Testing user access...")
        for user in keycloak_users:
            username = user.get('username', user.get('email', '').split('@')[0])
            if 'admin' in username.lower() or 'admin' in user.get('email', '').lower():
                roles = ['admin']
            else:
                roles = ['user']
            
            self.test_user_access(username, roles)
        
        return True

def main():
    """Main function"""
    setup = KubernetesUserSetup()
    if setup.run_complete_setup():
        print("\n✅ Kubernetes user setup completed successfully!")
        print("\n📋 Next steps:")
        print("   1. Configure your MCP server to use these ServiceAccount tokens")
        print("   2. Update your MCP server to impersonate users based on Keycloak identity")
        print("   3. Test the integration")
    else:
        print("\n❌ Kubernetes user setup failed!")
        exit(1)

if __name__ == "__main__":
    main() 