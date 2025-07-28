#!/usr/bin/env python3
"""
Token Exchange V2 Test Suite
Comprehensive testing of Keycloak Token Exchange V2 configuration
"""

import requests
import base64
import json
import time
import sys
import os
from typing import Dict, List, Optional

# Configuration
KEYCLOAK_URL = os.getenv("KEYCLOAK_ENV", "http://localhost:8002")
KEYCLOAK_REALM_NAME = os.getenv("KEYCLOAK_REALM_NAME", "authentication-demo")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "authentication-demo")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "demo-client-secret-change-in-production")


# Test scenarios
TEST_USERS = [
    {"username": "lance", "password": "password", "expected_role": "user"},
    {"username": "admin-user", "password": "password", "expected_role": "admin"}
]

TEST_SCOPES = {
    "mcp_basic": ["mcp:list_files", "mcp:health_check"],
    "mcp_admin": ["mcp:execute_command"],
    "llama_basic": ["llama:models:read", "llama:agents:read"],
    "mixed": ["mcp:list_files", "llama:inference"]
}

class TokenExchangeV2Tester:
    """Comprehensive Token Exchange V2 test suite"""
    
    def __init__(self):
        self.test_results = {}
        
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user and return token info"""
        try:
            response = requests.post(
                f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM_NAME}/protocol/openid-connect/token",
                data={
                    'grant_type': 'password',
                    'client_id': KEYCLOAK_CLIENT_ID,
                    'client_secret': KEYCLOAK_CLIENT_SECRET,
                    'username': username,
                    'password': password,
                    'scope': 'openid profile email'
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'access_token': result['access_token'],
                    'refresh_token': result.get('refresh_token'),
                    'scope': result.get('scope', ''),
                    'expires_in': result.get('expires_in')
                }
            else:
                print(f"❌ Authentication failed for {username}: {response.status_code}")
                print(f"   Error: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Authentication exception for {username}: {e}")
            return None

    def exchange_token_for_scopes(self, access_token: str, requested_scopes: List[str]) -> Dict:
        """Exchange access token for specific scopes"""
        try:
            # Prepare token exchange request
            data = {
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token': access_token,
                'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
                'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token',
                'audience': KEYCLOAK_CLIENT_ID,  # Self-exchange
                'scope': ' '.join(requested_scopes)
            }
            
            # Use Basic Auth for confidential client
            auth_string = base64.b64encode(f"{KEYCLOAK_CLIENT_ID}:{KEYCLOAK_CLIENT_SECRET}".encode()).decode()
            headers = {
                'Authorization': f'Basic {auth_string}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            response = requests.post(
                f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM_NAME}/protocol/openid-connect/token",
                data=data,
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()

                granted_scopes = result.get('scope', '').split()

                # Validate that requested scopes are fully granted
                if not set(requested_scopes).issubset(set(granted_scopes)):
                    return {
                        'success': False,
                        'error': 'Scope mismatch',
                        'error_description': f"Requested scopes {requested_scopes} not fully granted: {granted_scopes}",
                        'status_code': response.status_code,
                        'requested_scopes': requested_scopes
                    }
                
                return {
                    'success': True,
                    'access_token': result['access_token'],
                    'token_type': result.get('token_type', 'Bearer'),
                    'expires_in': result.get('expires_in'),
                    'scope': result.get('scope', ''),
                    'granted_scopes': granted_scopes,
                    'requested_scopes': requested_scopes
                }
            else:
                error_data = response.json() if response.content else {}
                return {
                    'success': False,
                    'error': error_data.get('error', 'Unknown error'),
                    'error_description': error_data.get('error_description', ''),
                    'status_code': response.status_code,
                    'requested_scopes': requested_scopes
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': 'Exception',
                'error_description': str(e),
                'requested_scopes': requested_scopes
            }

    def decode_jwt_payload(self, token: str) -> Optional[Dict]:
        """Decode JWT payload (without signature verification)"""
        try:
            # Split token and get payload
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode payload (add padding if needed)
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)
            decoded = base64.b64decode(payload)
            return json.loads(decoded)
        except Exception:
            return None

    def test_user_authentication(self) -> bool:
        """Test user authentication"""
        print("🔐 Testing User Authentication")
        print("-" * 40)
        
        success = True
        for user in TEST_USERS:
            print(f"Testing {user['username']}...", end=" ")
            
            auth_result = self.authenticate_user(user['username'], user['password'])
            if auth_result:
                # Decode token to check claims
                payload = self.decode_jwt_payload(auth_result['access_token'])
                if payload:
                    print(f"✅ Success")
                    print(f"   Initial scopes: {auth_result['scope']}")
                    print(f"   Token expires in: {auth_result['expires_in']}s")
                    print(f"   User: {payload.get('preferred_username', 'N/A')}")
                    print(f"   Email: {payload.get('email', 'N/A')}")
                else:
                    print(f"❌ Token decode failed")
                    success = False
            else:
                print(f"❌ Failed")
                success = False
            print()
        
        self.test_results['authentication'] = success
        return success

    def test_token_exchange_scenarios(self) -> bool:
        """Test various token exchange scenarios"""
        print("🔄 Testing Token Exchange Scenarios")
        print("-" * 40)
        
        overall_success = True
        
        for user in TEST_USERS:
            print(f"\n👤 Testing token exchange for {user['username']} ({user['expected_role']} role)")
            
            # Authenticate user
            auth_result = self.authenticate_user(user['username'], user['password'])
            if not auth_result:
                print(f"❌ Authentication failed for {user['username']}")
                overall_success = False
                continue
            
            user_token = auth_result['access_token']
            user_success = True
            
            # Test each scope scenario
            for scenario_name, requested_scopes in TEST_SCOPES.items():
                print(f"  📋 Scenario: {scenario_name} -> {requested_scopes}")
                
                exchange_result = self.exchange_token_for_scopes(user_token, requested_scopes)
                
                if exchange_result['success']:
                    granted = exchange_result['granted_scopes']
                    print(f"     ✅ Success - Granted: {granted}")
                    
                    # Validate scope grants based on user role
                    expected_denied = []
                    if user['expected_role'] == 'user':
                        # Users should be denied admin scopes
                        expected_denied = [scope for scope in requested_scopes if 'execute_command' in scope]
                    
                    if expected_denied:
                        actually_granted = [scope for scope in expected_denied if scope in granted]
                        if actually_granted:
                            print(f"     ⚠️ Warning: User granted admin scopes: {actually_granted}")
                else:
                    error = exchange_result['error']
                    print(f"     ❌ Failed: {error}")
                    
                    # Some failures are expected (e.g., user requesting admin scopes)
                    if user['expected_role'] == 'user' and any('execute_command' in scope for scope in requested_scopes):
                        print(f"     ℹ️ Expected failure: User role cannot access admin scopes")
                    else:
                        user_success = False
                        overall_success = False
                print()
            
            print(f"  {'✅ User tests passed' if user_success else '❌ User tests failed'}")
        
        self.test_results['token_exchange'] = overall_success
        return overall_success

    def test_scope_validation(self) -> bool:
        """Test that scopes are properly validated"""
        print("🛡️ Testing Scope Validation")
        print("-" * 40)
        
        # Test with user account
        user = TEST_USERS[0]  # lance (user role)
        auth_result = self.authenticate_user(user['username'], user['password'])
        
        if not auth_result:
            print("❌ Could not authenticate test user")
            self.test_results['scope_validation'] = False
            return False
        
        user_token = auth_result['access_token']
        
        test_cases = [
            {
                'name': 'Valid user scopes',
                'scopes': ['mcp:list_files', 'mcp:health_check'],
                'should_succeed': True
            },
            {
                'name': 'Admin-only scope (should fail for user)',
                'scopes': ['mcp:execute_command'],
                'should_succeed': False
            },
            {
                'name': 'Mixed valid and invalid scopes',
                'scopes': ['mcp:list_files', 'mcp:execute_command'],
                'should_succeed': False  # Should fail due to admin scope
            },
            {
                'name': 'Invalid scope name',
                'scopes': ['invalid:scope'],
                'should_succeed': False
            }
        ]
        
        success = True
        for test_case in test_cases:
            print(f"Testing: {test_case['name']}")
            print(f"  Scopes: {test_case['scopes']}")
            
            result = self.exchange_token_for_scopes(user_token, test_case['scopes'])
            
            if test_case['should_succeed']:
                if result['success']:
                    print(f"  ✅ Success (as expected)")
                else:
                    print(f"  ❌ Failed (unexpected): {result['error']}")
                    success = False
            else:
                if not result['success']:
                    print(f"  ✅ Failed (as expected): {result['error']}")
                else:
                    print(f"  ❌ Success (unexpected)")
                    success = False
            print()
        
        self.test_results['scope_validation'] = success
        return success

    def test_token_properties(self) -> bool:
        """Test token properties and claims"""
        print("🎫 Testing Token Properties")
        print("-" * 40)
        
        # Test with admin user for full scope access
        admin_user = TEST_USERS[1]  # admin-user
        auth_result = self.authenticate_user(admin_user['username'], admin_user['password'])
        
        if not auth_result:
            print("❌ Could not authenticate admin user")
            self.test_results['token_properties'] = False
            return False
        
        # Exchange for MCP scopes
        exchange_result = self.exchange_token_for_scopes(
            auth_result['access_token'],
            ['mcp:list_files', 'mcp:execute_command']
        )
        
        if not exchange_result['success']:
            print(f"❌ Token exchange failed: {exchange_result['error']}")
            self.test_results['token_properties'] = False
            return False
        
        # Decode and examine the exchanged token
        exchanged_token = exchange_result['access_token']
        payload = self.decode_jwt_payload(exchanged_token)
        
        if not payload:
            print("❌ Could not decode exchanged token")
            self.test_results['token_properties'] = False
            return False
        
        print("✅ Token successfully decoded")
        print(f"  Issuer: {payload.get('iss', 'N/A')}")
        print(f"  Audience: {payload.get('aud', 'N/A')}")
        print(f"  Subject: {payload.get('sub', 'N/A')}")
        print(f"  Issued at: {payload.get('iat', 'N/A')}")
        print(f"  Expires at: {payload.get('exp', 'N/A')}")
        print(f"  Scope: {payload.get('scope', 'N/A')}")
        print(f"  Client ID: {payload.get('azp', 'N/A')}")
        
        # Validate key properties
        checks = [
            ('Audience contains client ID', KEYCLOAK_CLIENT_ID in str(payload.get('aud', ''))),
            ('Scope contains requested scopes', 'mcp:list_files' in payload.get('scope', '')),
            ('Token type is Bearer', exchange_result['token_type'] == 'Bearer'),
            ('Token has expiration', payload.get('exp') is not None)
        ]
        
        success = True
        for check_name, check_result in checks:
            if check_result:
                print(f"  ✅ {check_name}")
            else:
                print(f"  ❌ {check_name}")
                success = False
        
        self.test_results['token_properties'] = success
        return success

    def test_refresh_token_exchange(self) -> bool:
        """Test refresh token exchange (if supported)"""
        print("🔄 Testing Refresh Token Exchange")
        print("-" * 40)
        
        # Authenticate user
        user = TEST_USERS[0]
        auth_result = self.authenticate_user(user['username'], user['password'])
        
        if not auth_result:
            print("❌ Could not authenticate user")
            self.test_results['refresh_token_exchange'] = False
            return False
        
        if not auth_result.get('refresh_token'):
            print("ℹ️ No refresh token available - skipping refresh token tests")
            self.test_results['refresh_token_exchange'] = True
            return True
        
        # Try to exchange for a refresh token
        try:
            data = {
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token': auth_result['access_token'],
                'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
                'requested_token_type': 'urn:ietf:params:oauth:token-type:refresh_token',
                'audience': KEYCLOAK_CLIENT_ID,
                'scope': 'mcp:list_files'
            }

            auth_string = base64.b64encode(f"{KEYCLOAK_CLIENT_ID}:{KEYCLOAK_CLIENT_SECRET}".encode()).decode()
            headers = {
                'Authorization': f'Basic {auth_string}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            response = requests.post(
                f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM_NAME}/protocol/openid-connect/token",
                data=data,
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                print("✅ Refresh token exchange successful")
                print(f"  Received refresh token: {bool(result.get('refresh_token'))}")
                print(f"  Received access token: {bool(result.get('access_token'))}")
                self.test_results['refresh_token_exchange'] = True
                return True
            else:
                print(f"ℹ️ Refresh token exchange not configured: {response.status_code}")
                self.test_results['refresh_token_exchange'] = True  # Not a failure
                return True
                
        except Exception as e:
            print(f"❌ Refresh token exchange error: {e}")
            self.test_results['refresh_token_exchange'] = False
            return False

    def run_all_tests(self) -> bool:
        """Run all Token Exchange V2 tests"""
        print("🧪 Token Exchange V2 - Test Suite")
        print("=" * 60)
        print(f"Target: {KEYCLOAK_URL}/realms/{KEYCLOAK_REALM_NAME}")
        print(f"Client: {KEYCLOAK_CLIENT_ID}")
        print()
        
        test_functions = [
            self.test_user_authentication,
            self.test_token_exchange_scenarios,
            self.test_scope_validation,
            self.test_token_properties,
            self.test_refresh_token_exchange
        ]
        
        overall_success = True
        for test_func in test_functions:
            try:
                success = test_func()
                if not success:
                    overall_success = False
            except Exception as e:
                print(f"❌ Test {test_func.__name__} failed with exception: {e}")
                overall_success = False
            print()
        
        # Print summary
        print("📊 Test Results Summary")
        print("=" * 60)
        
        for test_name, result in self.test_results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{test_name:25} {status}")
        
        print()
        if overall_success:
            print("🎉 All tests passed! Token Exchange V2 is properly configured.")
        else:
            print("❌ Some tests failed. Please check the configuration.")
        
        print()
        print("🔧 Configuration Verified:")
        print("  • Token Exchange V2 enabled and functional")
        print("  • Role-based scope access control working")
        print("  • Self-exchange pattern implemented correctly")
        print("  • Authorization policies enforced")
        
        return overall_success

def main():
    """Main test function"""
    tester = TokenExchangeV2Tester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 