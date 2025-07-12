import base64
import hashlib
import os
import urllib.parse
import requests
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging

logger = logging.getLogger(__name__)

def generate_pkce_pair():
    """Generate PKCE code verifier and challenge"""
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode('utf-8')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).rstrip(b'=').decode('utf-8')
    return code_verifier, code_challenge

class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """Handle OAuth callback from Keycloak"""
    def do_GET(self):
        print(f"Received callback: {self.path}")
        
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        self.server.auth_code = params.get("code", [None])[0]
        self.server.error = params.get("error", [None])[0]
        
        print(f"Auth code: {self.server.auth_code}")
        print(f"Error: {self.server.error}")
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        if self.server.auth_code:
            html = """
            <html>
            <head><title>Authentication Successful</title></head>
            <body>
                <h1>Authentication Successful!</h1>
                <p>You may close this window.</p>
                <script>
                    setTimeout(function() {
                        window.close();
                    }, 3000);
                </script>
            </body>
            </html>
            """
            self.wfile.write(html.encode())
        else:
            error_desc = params.get("error_description", ["Unknown error"])[0]
            html = f"""
            <html>
            <head><title>Authentication Failed</title></head>
            <body>
                <h1>Authentication Failed!</h1>
                <p>Error: {error_desc}</p>
            </body>
            </html>
            """
            self.wfile.write(html.encode())

    def log_message(self, format, *args):
        """Suppress default HTTP server logging"""
        pass

def get_oidc_token(
    keycloak_host,
    realm,
    client_id,
    client_secret=None,
    redirect_uri="http://localhost:8081/callback",  # Changed from 8080 to 8081
    scope="openid profile email",
    verify_ssl=True
):
    auth_url = f"{keycloak_host}/realms/{realm}/protocol/openid-connect/auth"
    token_url = f"{keycloak_host}/realms/{realm}/protocol/openid-connect/token"
    
    # Generate PKCE parameters
    code_verifier, code_challenge = generate_pkce_pair()
    
    # Build authorization URL
    params = {
        "client_id": client_id,
        "response_type": "code",
        "scope": scope,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_request_url = f"{auth_url}?{urllib.parse.urlencode(params)}"
    
    logger.info("Opening browser for Keycloak authentication...")
    print(f"Opening browser for authentication: {auth_request_url}")
    webbrowser.open(auth_request_url)
    
    # Start local server to catch callback
    print("Starting local server on http://localhost:8081/callback")  # Updated message
    print("Waiting for authentication callback...")
    
    try:
        httpd = HTTPServer(('localhost', 8081), OAuthCallbackHandler)  # Changed port
        print("Server started, waiting for callback...")
        httpd.handle_request()
        print("Callback received, processing...")
        
        if httpd.error:
            raise Exception(f"Authentication failed: {httpd.error}")
        
        if not httpd.auth_code:
            raise Exception("No authorization code received from Keycloak")
        
        print("Authorization code received, exchanging for tokens...")
        
        # Exchange authorization code for tokens
        token_data = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": httpd.auth_code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier
        }
        
        if client_secret:
            token_data["client_secret"] = client_secret
        
        print(f"Exchanging token at: {token_url}")
        response = requests.post(token_url, data=token_data, verify=verify_ssl)
        
        if response.status_code != 200:
            print(f"Token exchange failed: {response.status_code}")
            print(f"Response: {response.text}")
            response.raise_for_status()
        
        tokens = response.json()
        print("Tokens obtained successfully")
        
        return tokens
        
    except Exception as e:
        print(f"Error in token exchange: {e}")
        raise

def refresh_token(keycloak_host, realm, client_id, refresh_token, client_secret=None):
    """Refresh an expired access token"""
    token_url = f"{keycloak_host}/realms/{realm}/protocol/openid-connect/token"
    
    data = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token
    }
    
    if client_secret:
        data["client_secret"] = client_secret
    
    response = requests.post(token_url, data=data)
    response.raise_for_status()
    
    return response.json() 