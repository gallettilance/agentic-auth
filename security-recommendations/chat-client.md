# Chat Client Security & Usability Recommendations

**Component**: Web-based Chat Client (OAuth Client)  
**Role**: Public OAuth client providing user interface for AI interactions  
**Security Level**: **HIGH** - Handles user credentials, tokens, and sensitive conversations

## 🛡️ **Security Recommendations**

### **1. OAuth 2.1 Public Client Security**

#### **PKCE Implementation (Mandatory)**
```javascript
// PKCE implementation for public OAuth clients
class PKCEManager {
    /**
     * OAuth 2.1 PKCE implementation for browser-based clients.
     * Mandatory for all public clients per OAuth 2.1 specification.
     */
    
    constructor() {
        this.codeVerifier = null;
        this.codeChallenge = null;
    }
    
    async generateCodeChallenge() {
        // Generate cryptographically secure code verifier
        this.codeVerifier = this.generateCodeVerifier();
        
        // Generate SHA256 code challenge
        const encoder = new TextEncoder();
        const data = encoder.encode(this.codeVerifier);
        const digest = await crypto.subtle.digest('SHA-256', data);
        
        this.codeChallenge = this.base64URLEncode(digest);
        return this.codeChallenge;
    }
    
    generateCodeVerifier() {
        // Generate 128 character URL-safe string
        const array = new Uint8Array(96); // 96 bytes = 128 base64url chars
        crypto.getRandomValues(array);
        return this.base64URLEncode(array);
    }
    
    base64URLEncode(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }
    
    getCodeVerifier() {
        return this.codeVerifier;
    }
}

// Usage in authorization flow
const pkce = new PKCEManager();
const codeChallenge = await pkce.generateCodeChallenge();

// Redirect to authorization server
const authUrl = new URL('https://auth.example.com/oauth/authorize');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('redirect_uri', 'https://your-app.com/callback');
authUrl.searchParams.set('scope', 'openid profile chat_access');
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');
authUrl.searchParams.set('state', generateSecureState());

window.location.href = authUrl.toString();
```

#### **Secure Token Storage**
```javascript
// Secure token storage for browser-based applications
class SecureTokenStorage {
    /**
     * Secure token storage using multiple strategies.
     * Implements defense-in-depth for token protection.
     */
    
    constructor() {
        this.storage = this.selectBestStorage();
        this.encryptionKey = null;
        this.initializeEncryption();
    }
    
    selectBestStorage() {
        // Prefer sessionStorage for access tokens (cleared on tab close)
        if (typeof sessionStorage !== 'undefined') {
            return sessionStorage;
        }
        
        // Fallback to memory storage
        return new Map();
    }
    
    async initializeEncryption() {
        // Generate encryption key for additional token protection
        this.encryptionKey = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }
    
    async storeToken(tokenType, token, expiresIn = null) {
        try {
            // Encrypt token before storage
            const encryptedToken = await this.encryptToken(token);
            
            const tokenData = {
                token: encryptedToken,
                timestamp: Date.now(),
                expiresIn: expiresIn
            };
            
            this.storage.setItem(`token_${tokenType}`, JSON.stringify(tokenData));
            
            // Set automatic cleanup for expired tokens
            if (expiresIn) {
                setTimeout(() => {
                    this.removeToken(tokenType);
                }, expiresIn * 1000);
            }
            
        } catch (error) {
            console.error('Token storage failed:', error);
            throw new Error('Failed to store token securely');
        }
    }
    
    async getToken(tokenType) {
        try {
            const storedData = this.storage.getItem(`token_${tokenType}`);
            if (!storedData) return null;
            
            const tokenData = JSON.parse(storedData);
            
            // Check if token is expired
            if (this.isTokenExpired(tokenData)) {
                this.removeToken(tokenType);
                return null;
            }
            
            // Decrypt and return token
            return await this.decryptToken(tokenData.token);
            
        } catch (error) {
            console.error('Token retrieval failed:', error);
            return null;
        }
    }
    
    async encryptToken(token) {
        const encoder = new TextEncoder();
        const data = encoder.encode(token);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            this.encryptionKey,
            data
        );
        
        // Combine IV and encrypted data
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);
        
        return btoa(String.fromCharCode(...combined));
    }
    
    async decryptToken(encryptedToken) {
        const combined = new Uint8Array(
            atob(encryptedToken).split('').map(c => c.charCodeAt(0))
        );
        
        const iv = combined.slice(0, 12);
        const encrypted = combined.slice(12);
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            this.encryptionKey,
            encrypted
        );
        
        return new TextDecoder().decode(decrypted);
    }
    
    isTokenExpired(tokenData) {
        if (!tokenData.expiresIn) return false;
        
        const expirationTime = tokenData.timestamp + (tokenData.expiresIn * 1000);
        return Date.now() > expirationTime;
    }
    
    removeToken(tokenType) {
        this.storage.removeItem(`token_${tokenType}`);
    }
    
    clearAllTokens() {
        const keys = Object.keys(this.storage);
        keys.forEach(key => {
            if (key.startsWith('token_')) {
                this.storage.removeItem(key);
            }
        });
    }
}
```

### **2. CSRF and State Parameter Protection**

#### **Comprehensive CSRF Protection**
```javascript
// CSRF protection for OAuth flows
class CSRFProtection {
    /**
     * Comprehensive CSRF protection for OAuth authorization flows.
     * Implements state parameter validation and additional security measures.
     */
    
    constructor() {
        this.pendingStates = new Map();
        this.csrfTokens = new Map();
    }
    
    generateSecureState() {
        // Generate cryptographically secure state parameter
        const stateBytes = crypto.getRandomValues(new Uint8Array(32));
        const state = btoa(String.fromCharCode(...stateBytes))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        
        // Store state with timestamp for validation
        this.pendingStates.set(state, {
            timestamp: Date.now(),
            origin: window.location.origin
        });
        
        // Clean up old states (5 minute expiry)
        setTimeout(() => {
            this.pendingStates.delete(state);
        }, 5 * 60 * 1000);
        
        return state;
    }
    
    validateState(receivedState) {
        const stateData = this.pendingStates.get(receivedState);
        
        if (!stateData) {
            throw new Error('Invalid or expired state parameter');
        }
        
        // Check state age (max 5 minutes)
        const age = Date.now() - stateData.timestamp;
        if (age > 5 * 60 * 1000) {
            this.pendingStates.delete(receivedState);
            throw new Error('State parameter expired');
        }
        
        // Validate origin
        if (stateData.origin !== window.location.origin) {
            throw new Error('State parameter origin mismatch');
        }
        
        // Remove used state
        this.pendingStates.delete(receivedState);
        return true;
    }
    
    generateCSRFToken() {
        // Generate CSRF token for API requests
        const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
        const token = btoa(String.fromCharCode(...tokenBytes));
        
        this.csrfTokens.set(token, Date.now());
        return token;
    }
    
    validateCSRFToken(token) {
        const timestamp = this.csrfTokens.get(token);
        
        if (!timestamp) {
            return false;
        }
        
        // Check token age (max 1 hour)
        const age = Date.now() - timestamp;
        if (age > 60 * 60 * 1000) {
            this.csrfTokens.delete(token);
            return false;
        }
        
        return true;
    }
}
```

### **3. Content Security Policy (CSP)**

#### **Strict CSP Implementation**
```html
<!-- Strict Content Security Policy for chat applications -->
<meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;
    style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
    font-src 'self' https://fonts.gstatic.com;
    img-src 'self' data: https:;
    media-src 'self' https:;
    connect-src 'self' https://api.example.com https://auth.example.com wss://websocket.example.com;
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self' https://auth.example.com;
    upgrade-insecure-requests;
    block-all-mixed-content;
">

<!-- Additional security headers -->
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<meta http-equiv="X-Frame-Options" content="DENY">
<meta http-equiv="X-XSS-Protection" content="1; mode=block">
<meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
```

#### **CSP Violation Reporting**
```javascript
// CSP violation reporting and handling
class CSPViolationHandler {
    /**
     * Handle and report Content Security Policy violations.
     * Provides security monitoring and incident response.
     */
    
    constructor(reportingEndpoint) {
        this.reportingEndpoint = reportingEndpoint;
        this.setupViolationListener();
    }
    
    setupViolationListener() {
        document.addEventListener('securitypolicyviolation', (event) => {
            this.handleViolation(event);
        });
    }
    
    handleViolation(event) {
        const violation = {
            blockedURI: event.blockedURI,
            violatedDirective: event.violatedDirective,
            originalPolicy: event.originalPolicy,
            sourceFile: event.sourceFile,
            lineNumber: event.lineNumber,
            columnNumber: event.columnNumber,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            documentURI: document.location.href
        };
        
        // Log violation locally
        console.warn('CSP Violation:', violation);
        
        // Report to security monitoring system
        this.reportViolation(violation);
        
        // Take defensive action for critical violations
        if (this.isCriticalViolation(violation)) {
            this.handleCriticalViolation(violation);
        }
    }
    
    async reportViolation(violation) {
        try {
            await fetch(this.reportingEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(violation)
            });
        } catch (error) {
            console.error('Failed to report CSP violation:', error);
        }
    }
    
    isCriticalViolation(violation) {
        const criticalDirectives = [
            'script-src',
            'object-src',
            'base-uri',
            'form-action'
        ];
        
        return criticalDirectives.some(directive => 
            violation.violatedDirective.startsWith(directive)
        );
    }
    
    handleCriticalViolation(violation) {
        // Log out user and clear tokens for critical violations
        if (violation.violatedDirective.startsWith('script-src')) {
            this.emergencyLogout('Critical CSP violation detected');
        }
    }
    
    emergencyLogout(reason) {
        // Clear all tokens and session data
        const tokenStorage = new SecureTokenStorage();
        tokenStorage.clearAllTokens();
        
        // Redirect to login page
        window.location.href = '/login?error=security_violation';
    }
}
```

### **4. Input Validation and XSS Prevention**

#### **Comprehensive Input Sanitization**
```javascript
// Input validation and XSS prevention
class InputSanitizer {
    /**
     * Comprehensive input sanitization for chat applications.
     * Prevents XSS, injection attacks, and malicious content.
     */
    
    constructor() {
        this.dangerousPatterns = [
            // Script injection patterns
            /<script[^>]*>.*?<\/script>/gi,
            /javascript:/gi,
            /vbscript:/gi,
            /on\w+\s*=/gi,
            
            // HTML injection patterns
            /<iframe[^>]*>.*?<\/iframe>/gi,
            /<object[^>]*>.*?<\/object>/gi,
            /<embed[^>]*>.*?<\/embed>/gi,
            /<form[^>]*>.*?<\/form>/gi,
            
            // URL patterns
            /data:text\/html/gi,
            /data:application\/javascript/gi,
            
            // CSS injection patterns
            /<style[^>]*>.*?<\/style>/gi,
            /expression\s*\(/gi,
            /@import/gi
        ];
        
        this.maxInputLength = 10000;
        this.maxMessageLength = 2000;
    }
    
    sanitizeUserInput(input, context = 'general') {
        if (typeof input !== 'string') {
            throw new Error('Input must be a string');
        }
        
        // Check input length
        if (input.length > this.maxInputLength) {
            throw new Error('Input exceeds maximum length');
        }
        
        // Apply context-specific sanitization
        switch (context) {
            case 'message':
                return this.sanitizeMessage(input);
            case 'username':
                return this.sanitizeUsername(input);
            case 'search':
                return this.sanitizeSearchQuery(input);
            default:
                return this.sanitizeGeneral(input);
        }
    }
    
    sanitizeMessage(message) {
        // Check message length
        if (message.length > this.maxMessageLength) {
            throw new Error('Message exceeds maximum length');
        }
        
        // Remove dangerous patterns
        let sanitized = message;
        this.dangerousPatterns.forEach(pattern => {
            sanitized = sanitized.replace(pattern, '');
        });
        
        // Encode HTML entities
        sanitized = this.encodeHTMLEntities(sanitized);
        
        // Validate URLs in message
        sanitized = this.sanitizeURLs(sanitized);
        
        return sanitized.trim();
    }
    
    sanitizeUsername(username) {
        // Strict validation for usernames
        const usernamePattern = /^[a-zA-Z0-9_-]+$/;
        
        if (!usernamePattern.test(username)) {
            throw new Error('Username contains invalid characters');
        }
        
        if (username.length > 50) {
            throw new Error('Username too long');
        }
        
        return username.toLowerCase();
    }
    
    sanitizeSearchQuery(query) {
        // Remove potentially dangerous search patterns
        let sanitized = query.replace(/[<>\"']/g, '');
        
        // Limit query length
        if (sanitized.length > 200) {
            sanitized = sanitized.substring(0, 200);
        }
        
        return sanitized.trim();
    }
    
    sanitizeGeneral(input) {
        // General sanitization for form inputs
        let sanitized = input;
        
        // Remove dangerous patterns
        this.dangerousPatterns.forEach(pattern => {
            sanitized = sanitized.replace(pattern, '');
        });
        
        // Encode HTML entities
        sanitized = this.encodeHTMLEntities(sanitized);
        
        return sanitized.trim();
    }
    
    encodeHTMLEntities(text) {
        const entityMap = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '/': '&#x2F;'
        };
        
        return text.replace(/[&<>"'\/]/g, (s) => entityMap[s]);
    }
    
    sanitizeURLs(text) {
        // Find and validate URLs in text
        const urlPattern = /(https?:\/\/[^\s]+)/g;
        
        return text.replace(urlPattern, (url) => {
            try {
                const urlObj = new URL(url);
                
                // Only allow HTTP/HTTPS protocols
                if (!['http:', 'https:'].includes(urlObj.protocol)) {
                    return '[INVALID URL]';
                }
                
                // Block suspicious domains
                if (this.isSuspiciousDomain(urlObj.hostname)) {
                    return '[BLOCKED URL]';
                }
                
                return url;
            } catch (error) {
                return '[INVALID URL]';
            }
        });
    }
    
    isSuspiciousDomain(hostname) {
        const suspiciousDomains = [
            'bit.ly',
            'tinyurl.com',
            'localhost',
            '127.0.0.1',
            // Add more suspicious domains as needed
        ];
        
        return suspiciousDomains.includes(hostname.toLowerCase());
    }
}
```

### **5. Session Management and Security**

#### **Secure Session Handling**
```javascript
// Secure session management for chat applications
class SecureSessionManager {
    /**
     * Secure session management with automatic cleanup and security monitoring.
     * Handles session lifecycle, token refresh, and security events.
     */
    
    constructor(tokenStorage, authService) {
        this.tokenStorage = tokenStorage;
        this.authService = authService;
        this.sessionTimeout = 30 * 60 * 1000; // 30 minutes
        this.refreshThreshold = 5 * 60 * 1000; // 5 minutes before expiry
        this.activityTimer = null;
        this.refreshTimer = null;
        
        this.setupActivityMonitoring();
        this.setupTokenRefresh();
    }
    
    setupActivityMonitoring() {
        // Monitor user activity for session timeout
        const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
        
        events.forEach(event => {
            document.addEventListener(event, () => {
                this.resetActivityTimer();
            }, { passive: true });
        });
        
        this.resetActivityTimer();
    }
    
    resetActivityTimer() {
        if (this.activityTimer) {
            clearTimeout(this.activityTimer);
        }
        
        this.activityTimer = setTimeout(() => {
            this.handleSessionTimeout();
        }, this.sessionTimeout);
    }
    
    setupTokenRefresh() {
        // Automatically refresh tokens before expiry
        this.refreshTimer = setInterval(() => {
            this.checkTokenRefresh();
        }, 60 * 1000); // Check every minute
    }
    
    async checkTokenRefresh() {
        try {
            const accessToken = await this.tokenStorage.getToken('access');
            if (!accessToken) return;
            
            // Decode token to check expiry (if JWT)
            const tokenData = this.decodeJWT(accessToken);
            if (!tokenData) return;
            
            const expiryTime = tokenData.exp * 1000;
            const currentTime = Date.now();
            
            // Refresh if within threshold of expiry
            if (expiryTime - currentTime < this.refreshThreshold) {
                await this.refreshTokens();
            }
            
        } catch (error) {
            console.error('Token refresh check failed:', error);
        }
    }
    
    async refreshTokens() {
        try {
            const refreshToken = await this.tokenStorage.getToken('refresh');
            if (!refreshToken) {
                throw new Error('No refresh token available');
            }
            
            const newTokens = await this.authService.refreshTokens(refreshToken);
            
            // Store new tokens
            await this.tokenStorage.storeToken('access', newTokens.access_token, newTokens.expires_in);
            
            if (newTokens.refresh_token) {
                await this.tokenStorage.storeToken('refresh', newTokens.refresh_token);
            }
            
            console.log('Tokens refreshed successfully');
            
        } catch (error) {
            console.error('Token refresh failed:', error);
            this.handleAuthenticationFailure();
        }
    }
    
    handleSessionTimeout() {
        // Clear tokens and redirect to login
        this.tokenStorage.clearAllTokens();
        
        // Show timeout message
        this.showSessionTimeoutMessage();
        
        // Redirect to login after delay
        setTimeout(() => {
            window.location.href = '/login?reason=timeout';
        }, 3000);
    }
    
    handleAuthenticationFailure() {
        // Clear tokens and redirect to login
        this.tokenStorage.clearAllTokens();
        
        // Show authentication failure message
        this.showAuthenticationFailureMessage();
        
        // Redirect to login
        window.location.href = '/login?reason=auth_failure';
    }
    
    showSessionTimeoutMessage() {
        const message = document.createElement('div');
        message.className = 'session-timeout-message';
        message.innerHTML = `
            <div class="alert alert-warning">
                <h4>Session Timeout</h4>
                <p>Your session has expired due to inactivity. You will be redirected to login.</p>
            </div>
        `;
        document.body.appendChild(message);
    }
    
    showAuthenticationFailureMessage() {
        const message = document.createElement('div');
        message.className = 'auth-failure-message';
        message.innerHTML = `
            <div class="alert alert-danger">
                <h4>Authentication Failed</h4>
                <p>Your session is no longer valid. Please log in again.</p>
            </div>
        `;
        document.body.appendChild(message);
    }
    
    decodeJWT(token) {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return null;
            
            const payload = JSON.parse(atob(parts[1]));
            return payload;
        } catch (error) {
            return null;
        }
    }
    
    async logout() {
        // Clear timers
        if (this.activityTimer) {
            clearTimeout(this.activityTimer);
        }
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
        }
        
        // Revoke tokens on server
        try {
            const accessToken = await this.tokenStorage.getToken('access');
            if (accessToken) {
                await this.authService.revokeToken(accessToken);
            }
        } catch (error) {
            console.error('Token revocation failed:', error);
        }
        
        // Clear local tokens
        this.tokenStorage.clearAllTokens();
        
        // Redirect to login
        window.location.href = '/login';
    }
}
```

### **6. Error Handling and Security Monitoring**

#### **Comprehensive Error Handling**
```javascript
// Comprehensive error handling and security monitoring
class SecurityMonitor {
    /**
     * Security monitoring and incident response for chat applications.
     * Detects and responds to security events and anomalies.
     */
    
    constructor(reportingEndpoint) {
        this.reportingEndpoint = reportingEndpoint;
        this.errorCounts = new Map();
        this.securityEvents = [];
        this.maxErrorsPerMinute = 10;
        
        this.setupGlobalErrorHandler();
        this.setupSecurityEventMonitoring();
    }
    
    setupGlobalErrorHandler() {
        // Handle uncaught JavaScript errors
        window.addEventListener('error', (event) => {
            this.handleJavaScriptError(event);
        });
        
        // Handle unhandled promise rejections
        window.addEventListener('unhandledrejection', (event) => {
            this.handleUnhandledRejection(event);
        });
    }
    
    setupSecurityEventMonitoring() {
        // Monitor for security-related events
        document.addEventListener('securitypolicyviolation', (event) => {
            this.logSecurityEvent('csp_violation', {
                violatedDirective: event.violatedDirective,
                blockedURI: event.blockedURI
            });
        });
        
        // Monitor for suspicious activity
        this.monitorSuspiciousActivity();
    }
    
    handleJavaScriptError(event) {
        const error = {
            type: 'javascript_error',
            message: event.message,
            filename: event.filename,
            lineno: event.lineno,
            colno: event.colno,
            stack: event.error?.stack,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            url: window.location.href
        };
        
        this.logError(error);
        
        // Check for potential security implications
        if (this.isSecurityRelevantError(error)) {
            this.logSecurityEvent('security_relevant_error', error);
        }
    }
    
    handleUnhandledRejection(event) {
        const error = {
            type: 'unhandled_rejection',
            reason: event.reason?.toString(),
            stack: event.reason?.stack,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            url: window.location.href
        };
        
        this.logError(error);
        
        // Prevent default handling to avoid console spam
        event.preventDefault();
    }
    
    logError(error) {
        console.error('Application Error:', error);
        
        // Track error frequency
        const errorKey = `${error.type}_${error.message}`;
        const now = Date.now();
        
        if (!this.errorCounts.has(errorKey)) {
            this.errorCounts.set(errorKey, []);
        }
        
        const errorTimes = this.errorCounts.get(errorKey);
        errorTimes.push(now);
        
        // Clean old errors (older than 1 minute)
        const oneMinuteAgo = now - 60 * 1000;
        this.errorCounts.set(errorKey, errorTimes.filter(time => time > oneMinuteAgo));
        
        // Check for error flooding
        if (errorTimes.length > this.maxErrorsPerMinute) {
            this.logSecurityEvent('error_flooding', {
                errorType: error.type,
                count: errorTimes.length
            });
        }
        
        // Report error to monitoring system
        this.reportError(error);
    }
    
    logSecurityEvent(eventType, details) {
        const event = {
            type: eventType,
            details: details,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            url: window.location.href,
            sessionId: this.getSessionId()
        };
        
        this.securityEvents.push(event);
        console.warn('Security Event:', event);
        
        // Report critical security events immediately
        if (this.isCriticalSecurityEvent(eventType)) {
            this.reportSecurityEvent(event);
        }
    }
    
    isSecurityRelevantError(error) {
        const securityKeywords = [
            'unauthorized',
            'forbidden',
            'csrf',
            'xss',
            'injection',
            'token',
            'authentication',
            'authorization'
        ];
        
        const errorText = (error.message + ' ' + error.stack).toLowerCase();
        return securityKeywords.some(keyword => errorText.includes(keyword));
    }
    
    isCriticalSecurityEvent(eventType) {
        const criticalEvents = [
            'csp_violation',
            'error_flooding',
            'suspicious_activity',
            'token_theft_attempt'
        ];
        
        return criticalEvents.includes(eventType);
    }
    
    monitorSuspiciousActivity() {
        // Monitor for rapid-fire requests
        let requestCount = 0;
        const originalFetch = window.fetch;
        
        window.fetch = async (...args) => {
            requestCount++;
            
            // Reset counter every minute
            setTimeout(() => {
                requestCount = Math.max(0, requestCount - 1);
            }, 60 * 1000);
            
            // Flag suspicious request patterns
            if (requestCount > 100) {
                this.logSecurityEvent('suspicious_activity', {
                    type: 'rapid_requests',
                    count: requestCount
                });
            }
            
            return originalFetch.apply(this, args);
        };
    }
    
    async reportError(error) {
        try {
            await fetch(`${this.reportingEndpoint}/errors`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(error)
            });
        } catch (reportingError) {
            console.error('Failed to report error:', reportingError);
        }
    }
    
    async reportSecurityEvent(event) {
        try {
            await fetch(`${this.reportingEndpoint}/security`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(event)
            });
        } catch (reportingError) {
            console.error('Failed to report security event:', reportingError);
        }
    }
    
    getSessionId() {
        // Generate or retrieve session ID for tracking
        let sessionId = sessionStorage.getItem('session_id');
        if (!sessionId) {
            sessionId = crypto.randomUUID();
            sessionStorage.setItem('session_id', sessionId);
        }
        return sessionId;
    }
}
```

## 🚀 **Usability Recommendations**

### **1. Progressive Authentication**

#### **Seamless Login Experience**
```javascript
// Progressive authentication with smooth user experience
class ProgressiveAuth {
    /**
     * Progressive authentication system that gradually requests permissions.
     * Provides smooth user experience while maintaining security.
     */
    
    constructor(authService, tokenStorage) {
        this.authService = authService;
        this.tokenStorage = tokenStorage;
        this.permissionLevels = {
            'basic': ['openid', 'profile'],
            'chat': ['openid', 'profile', 'chat_access'],
            'advanced': ['openid', 'profile', 'chat_access', 'file_access'],
            'admin': ['openid', 'profile', 'chat_access', 'file_access', 'admin_access']
        };
    }
    
    async requestPermissions(level, context = null) {
        const requiredScopes = this.permissionLevels[level];
        const currentScopes = await this.getCurrentScopes();
        
        // Check if user already has required permissions
        if (this.hasRequiredScopes(currentScopes, requiredScopes)) {
            return true;
        }
        
        // Show permission explanation
        const userConsent = await this.showPermissionExplanation(level, context);
        if (!userConsent) {
            return false;
        }
        
        // Request additional permissions
        return await this.requestAdditionalScopes(requiredScopes);
    }
    
    async getCurrentScopes() {
        try {
            const accessToken = await this.tokenStorage.getToken('access');
            if (!accessToken) return [];
            
            const tokenData = this.decodeJWT(accessToken);
            return tokenData?.scope?.split(' ') || [];
        } catch (error) {
            return [];
        }
    }
    
    hasRequiredScopes(currentScopes, requiredScopes) {
        return requiredScopes.every(scope => currentScopes.includes(scope));
    }
    
    async showPermissionExplanation(level, context) {
        return new Promise((resolve) => {
            const modal = this.createPermissionModal(level, context);
            
            modal.querySelector('.approve-btn').addEventListener('click', () => {
                modal.remove();
                resolve(true);
            });
            
            modal.querySelector('.deny-btn').addEventListener('click', () => {
                modal.remove();
                resolve(false);
            });
            
            document.body.appendChild(modal);
        });
    }
    
    createPermissionModal(level, context) {
        const modal = document.createElement('div');
        modal.className = 'permission-modal';
        
        const explanations = {
            'chat': 'To start chatting, we need access to send messages and view your conversation history.',
            'advanced': 'Advanced features require additional permissions to access files and manage your data.',
            'admin': 'Administrative functions require elevated permissions to manage system settings.'
        };
        
        modal.innerHTML = `
            <div class="modal-overlay">
                <div class="modal-content">
                    <h3>Additional Permissions Required</h3>
                    <p>${explanations[level] || 'This feature requires additional permissions.'}</p>
                    ${context ? `<p><strong>Context:</strong> ${context}</p>` : ''}
                    <div class="permission-list">
                        <h4>Requested Permissions:</h4>
                        <ul>
                            ${this.permissionLevels[level].map(scope => 
                                `<li>${this.getPermissionDescription(scope)}</li>`
                            ).join('')}
                        </ul>
                    </div>
                    <div class="modal-actions">
                        <button class="approve-btn btn btn-primary">Grant Permissions</button>
                        <button class="deny-btn btn btn-secondary">Not Now</button>
                    </div>
                </div>
            </div>
        `;
        
        return modal;
    }
    
    getPermissionDescription(scope) {
        const descriptions = {
            'openid': 'Basic identity information',
            'profile': 'Your profile information',
            'chat_access': 'Send and receive messages',
            'file_access': 'Access your files',
            'admin_access': 'Administrative functions'
        };
        
        return descriptions[scope] || scope;
    }
    
    async requestAdditionalScopes(requiredScopes) {
        try {
            // Redirect to authorization server for additional scopes
            const authUrl = await this.authService.buildAuthorizationUrl({
                scopes: requiredScopes,
                prompt: 'consent' // Force consent screen for new permissions
            });
            
            window.location.href = authUrl;
            return true;
            
        } catch (error) {
            console.error('Failed to request additional scopes:', error);
            return false;
        }
    }
    
    decodeJWT(token) {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) return null;
            
            const payload = JSON.parse(atob(parts[1]));
            return payload;
        } catch (error) {
            return null;
        }
    }
}
```

### **2. User-Friendly Error Messages**

#### **Contextual Error Handling**
```javascript
// User-friendly error messages and recovery suggestions
class UserFriendlyErrorHandler {
    /**
     * Provides user-friendly error messages with recovery suggestions.
     * Helps users understand and resolve authentication issues.
     */
    
    constructor() {
        this.errorMessages = {
            'invalid_token': {
                title: 'Session Expired',
                message: 'Your session has expired. Please log in again.',
                action: 'Log In',
                actionUrl: '/login'
            },
            'insufficient_scope': {
                title: 'Additional Permissions Required',
                message: 'This feature requires additional permissions.',
                action: 'Grant Permissions',
                actionCallback: this.requestAdditionalPermissions
            },
            'rate_limit_exceeded': {
                title: 'Too Many Requests',
                message: 'Please wait a moment before trying again.',
                action: 'Retry',
                actionCallback: this.retryAfterDelay
            },
            'network_error': {
                title: 'Connection Problem',
                message: 'Please check your internet connection and try again.',
                action: 'Retry',
                actionCallback: this.retryRequest
            },
            'server_error': {
                title: 'Server Error',
                message: 'Something went wrong on our end. Please try again later.',
                action: 'Retry',
                actionCallback: this.retryRequest
            }
        };
    }
    
    handleError(error, context = null) {
        const errorInfo = this.categorizeError(error);
        this.showUserFriendlyError(errorInfo, context);
        
        // Log error for debugging
        console.error('User-facing error:', error);
        
        // Report error to monitoring system
        this.reportError(error, context);
    }
    
    categorizeError(error) {
        // Categorize error based on type, status code, or message
        if (error.name === 'TokenExpiredError' || error.status === 401) {
            return this.errorMessages['invalid_token'];
        }
        
        if (error.status === 403) {
            return this.errorMessages['insufficient_scope'];
        }
        
        if (error.status === 429) {
            return this.errorMessages['rate_limit_exceeded'];
        }
        
        if (error.name === 'NetworkError' || !navigator.onLine) {
            return this.errorMessages['network_error'];
        }
        
        if (error.status >= 500) {
            return this.errorMessages['server_error'];
        }
        
        // Generic error fallback
        return {
            title: 'Something Went Wrong',
            message: 'An unexpected error occurred. Please try again.',
            action: 'Retry',
            actionCallback: this.retryRequest
        };
    }
    
    showUserFriendlyError(errorInfo, context) {
        // Remove any existing error messages
        this.clearErrorMessages();
        
        const errorElement = document.createElement('div');
        errorElement.className = 'user-error-message';
        errorElement.innerHTML = `
            <div class="alert alert-warning">
                <div class="error-content">
                    <h4>${errorInfo.title}</h4>
                    <p>${errorInfo.message}</p>
                    ${context ? `<p><small>Context: ${context}</small></p>` : ''}
                </div>
                <div class="error-actions">
                    <button class="error-action-btn btn btn-primary">
                        ${errorInfo.action}
                    </button>
                    <button class="error-dismiss-btn btn btn-secondary">
                        Dismiss
                    </button>
                </div>
            </div>
        `;
        
        // Add event listeners
        const actionBtn = errorElement.querySelector('.error-action-btn');
        const dismissBtn = errorElement.querySelector('.error-dismiss-btn');
        
        actionBtn.addEventListener('click', () => {
            if (errorInfo.actionUrl) {
                window.location.href = errorInfo.actionUrl;
            } else if (errorInfo.actionCallback) {
                errorInfo.actionCallback();
            }
            this.clearErrorMessages();
        });
        
        dismissBtn.addEventListener('click', () => {
            this.clearErrorMessages();
        });
        
        // Add to page
        document.body.appendChild(errorElement);
        
        // Auto-dismiss after 10 seconds
        setTimeout(() => {
            this.clearErrorMessages();
        }, 10000);
    }
    
    clearErrorMessages() {
        const existingErrors = document.querySelectorAll('.user-error-message');
        existingErrors.forEach(error => error.remove());
    }
    
    async requestAdditionalPermissions() {
        // Redirect to permission request flow
        const progressiveAuth = new ProgressiveAuth();
        await progressiveAuth.requestPermissions('advanced');
    }
    
    async retryAfterDelay() {
        // Wait 5 seconds before retry
        await new Promise(resolve => setTimeout(resolve, 5000));
        window.location.reload();
    }
    
    retryRequest() {
        // Retry the last failed request
        window.location.reload();
    }
    
    reportError(error, context) {
        // Report error to monitoring system
        const errorReport = {
            error: error.toString(),
            context: context,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            url: window.location.href
        };
        
        // Send to monitoring endpoint
        fetch('/api/errors', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(errorReport)
        }).catch(console.error);
    }
}
```

## 🔧 **Implementation Checklist**

### **OAuth Security**
- [ ] Implement PKCE for all authorization flows
- [ ] Add secure token storage with encryption
- [ ] Implement CSRF protection with state validation
- [ ] Add comprehensive CSP with violation reporting
- [ ] Implement secure session management with timeout
- [ ] Add token refresh automation
- [ ] Implement progressive authentication
- [ ] Add security monitoring and alerting

### **Input Security**
- [ ] Implement comprehensive input sanitization
- [ ] Add XSS prevention measures
- [ ] Implement content validation for messages
- [ ] Add URL sanitization and validation
- [ ] Implement file upload security (if applicable)
- [ ] Add rate limiting for user actions
- [ ] Implement abuse detection and prevention
- [ ] Add content filtering for inappropriate material

### **Error Handling**
- [ ] Implement user-friendly error messages
- [ ] Add contextual error recovery suggestions
- [ ] Implement comprehensive error logging
- [ ] Add error categorization and prioritization
- [ ] Implement automated error reporting
- [ ] Add error analytics and monitoring
- [ ] Create error recovery workflows
- [ ] Implement graceful degradation

### **User Experience**
- [ ] Implement progressive permission requests
- [ ] Add smooth authentication flows
- [ ] Implement automatic token refresh
- [ ] Add session persistence across tabs
- [ ] Implement offline capability (if applicable)
- [ ] Add accessibility features
- [ ] Implement responsive design
- [ ] Add performance optimization

## 🎯 **Success Metrics**

### **Security Metrics**
- **Authentication Success Rate**: >99.5%
- **Token Security**: 0 token compromise incidents
- **XSS Prevention**: 100% of attempts blocked
- **CSRF Protection**: 100% of attacks prevented
- **Session Security**: <0.1% unauthorized access

### **User Experience Metrics**
- **Login Success Rate**: >98%
- **Authentication Time**: <3 seconds average
- **Error Resolution Rate**: >90% users recover successfully
- **User Satisfaction**: >95% positive feedback
- **Support Tickets**: <1% of users need help

### **Performance Metrics**
- **Page Load Time**: <2 seconds
- **Token Refresh Time**: <1 second
- **Error Recovery Time**: <5 seconds
- **Uptime**: >99.9%
- **Client-side Memory Usage**: <50MB 
- **Offline Functionality**: 80% features available offline 