#!/bin/bash

# 🛑 Stop Unified Authentication & Authorization Demo Services (Keycloak Edition)

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source "$SCRIPT_DIR/scripts/demo_utils.sh"

echo "🛑 Stopping Unified Authentication & Authorization Demo (Keycloak Edition)..."
echo "=========================================================================="

# Function to stop service by port
stop_by_port() {
    local port=$1
    local name=$2
    
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}🔄 Stopping $name (port $port)...${NC}"
        kill -9 $(lsof -Pi :$port -sTCP:LISTEN -t) 2>/dev/null || true
        echo -e "${GREEN}✅ $name stopped${NC}"
    else
        echo -e "${YELLOW}⚠️  $name not running on port $port${NC}"
    fi
}

# Function to stop service by PID
stop_by_pid() {
    local pid=$1
    local name=$2
    
    if [ -n "$pid" ] && kill -0 $pid 2>/dev/null; then
        echo -e "${YELLOW}🔄 Stopping $name (PID: $pid)...${NC}"
        kill -9 $pid 2>/dev/null || true
        echo -e "${GREEN}✅ $name stopped${NC}"
    fi
}

# Read PIDs from file if it exists
if [ -f demo_pids.txt ]; then
    echo "📋 Reading process IDs from demo_pids.txt..."
    read ADMIN_PID MCP_PID LLAMA_PID FRONTEND_PID < demo_pids.txt
    
    # Stop services by PID
    stop_by_pid "$FRONTEND_PID" "Chat Frontend"
    stop_by_pid "$LLAMA_PID" "Llama Stack"
    stop_by_pid "$ADMIN_PID" "Admin Dashboard"
    stop_by_pid "$MCP_PID" "MCP Server"
    
    # Remove PID file
    rm -f demo_pids.txt
    echo "🗑️  Removed demo_pids.txt"
else
    echo "⚠️  demo_pids.txt not found, stopping by port..."
fi

# Stop services by port (backup method)
echo ""
echo "🔍 Checking ports for any remaining processes..."
stop_by_port 5001 "Chat Frontend"
stop_by_port 8321 "Llama Stack"
stop_by_port 8003 "Admin Dashboard"
stop_by_port 8001 "MCP Server"

if [ "$KEYCLOAK_RUN_CONTAINER" = true ] ; then
    # Stop Keycloak
    echo ""
    echo -e "${BLUE}🔐 Stopping Keycloak...${NC}"
    if $CONTAINER_RUNTIME ps -q -f name=$KEYCLOAK_CONTAINER_NAME | grep -q .; then
        echo -e "${YELLOW}🔄 Stopping Keycloak container...${NC}"
        $CONTAINER_RUNTIME stop $KEYCLOAK_CONTAINER_NAME >/dev/null 2>&1
        echo -e "${GREEN}✅ Keycloak stopped${NC}"
    else
        echo -e "${YELLOW}⚠️  Keycloak container not running${NC}"
    fi
fi

# Note about Keycloak
echo ""
echo -e "${BLUE}ℹ️  Note: Keycloak container is preserved for next start${NC}"
echo -e "${BLUE}   Use: $SCRIPT_DIR/cleanup_demo.sh to remove it completely${NC}"

# Clear Keycloak SSO session
echo ""
echo "🔐 Clearing Keycloak SSO session..."

clear_keycloak_sso() {
    # Check if Keycloak is running
    if lsof -Pi :$KEYCLOAK_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}🔄 Logging out from Keycloak SSO...${NC}"
        
        if command -v curl >/dev/null 2>&1; then
            # Method 1: Clear all sessions via admin API
            echo -e "${YELLOW}🔄 Clearing all user sessions via admin API...${NC}"
            
            # Get admin token
            ADMIN_TOKEN=$(curl -s -X POST ${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -d "username=$KEYCLOAK_ADMIN&password=$KEYCLOAK_ADMIN_PASSWORD&grant_type=password&client_id=admin-cli" | \
                python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null) || true
            
            if [ -n "$ADMIN_TOKEN" ]; then
                # Clear all user sessions in the realm
                curl -s -X DELETE \
                    "${KEYCLOAK_URL}/admin/realms/$KEYCLOAK_REALM/sessions" \
                    -H "Authorization: Bearer $ADMIN_TOKEN" \
                    -H "Content-Type: application/json" >/dev/null 2>&1 || true
                    
                # Also clear all offline sessions
                curl -s -X DELETE \
                    "${KEYCLOAK_URL}/admin/realms/$KEYCLOAK_REALM/sessions/offline" \
                    -H "Authorization: Bearer $ADMIN_TOKEN" \
                    -H "Content-Type: application/json" >/dev/null 2>&1 || true
                    
                echo -e "${GREEN}✅ All user sessions cleared via admin API${NC}"
            else
                echo -e "${YELLOW}⚠️  Could not get admin token - trying direct logout${NC}"
                
                # Method 2: Force logout by hitting logout endpoint with proper params
                LOGOUT_URL="${KEYCLOAK_URL}/realms/$KEYCLOAK_REALM/protocol/openid-connect/logout"
                curl -s -X POST "$LOGOUT_URL" \
                    -H "Content-Type: application/x-www-form-urlencoded" \
                    -d "client_id=$OIDC_CLIENT_ID&post_logout_redirect_uri=http://localhost:5001" \
                    >/dev/null 2>&1 || true
                    
                # Also try the end session endpoint
                END_SESSION_URL="${KEYCLOAK_URL}/realms/$KEYCLOAK_REALM/protocol/openid-connect/logout"
                curl -s -X GET "$END_SESSION_URL?client_id=$OIDC_CLIENT_ID&post_logout_redirect_uri=http://localhost:5001" \
                    >/dev/null 2>&1 || true
                    
                echo -e "${GREEN}✅ Keycloak logout endpoints called${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️  curl not available - Keycloak SSO session may persist${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  Keycloak not running on port $KEYCLOAK_PORT - skipping SSO logout${NC}"
    fi
}

clear_keycloak_sso

# Force quit Chrome and clear authentication cookies
echo ""
echo "🍪 Force closing Chrome and clearing authentication cookies..."

cleanup_chrome_cookies() {
    # Force quit Chrome
    echo -e "${YELLOW}🔄 Force closing Chrome...${NC}"
    pkill -f "Google Chrome" 2>/dev/null || true
    sleep 2
    
    # Determine Chrome cookies path based on OS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS Chrome cookies
        CHROME_COOKIES="$HOME/Library/Application Support/Google/Chrome/Default/Cookies"
    else
        # Linux Chrome cookies
        CHROME_COOKIES="$HOME/.config/google-chrome/Default/Cookies"
    fi
    
    # Clear Chrome localhost and Keycloak cookies
    if [ -f "$CHROME_COOKIES" ] && command -v sqlite3 >/dev/null 2>&1; then
        echo -e "${YELLOW}🔄 Clearing Chrome localhost and Keycloak cookies...${NC}"
        # Clear localhost cookies (app sessions)
        sqlite3 "$CHROME_COOKIES" "DELETE FROM cookies WHERE host_key LIKE '%localhost%' OR host_key LIKE '%.localhost%';" 2>/dev/null || true
        # Clear any Keycloak-related cookies
        sqlite3 "$CHROME_COOKIES" "DELETE FROM cookies WHERE name LIKE '%keycloak%' OR name LIKE '%KEYCLOAK%' OR name LIKE '%KC_%';" 2>/dev/null || true
        echo -e "${GREEN}✅ Chrome localhost and Keycloak cookies cleared${NC}"
    else
        echo -e "${YELLOW}⚠️  Chrome cookies database not found or sqlite3 not available${NC}"
        echo -e "${YELLOW}   Chrome may not be installed or cookies are in a different location${NC}"
    fi
}

cleanup_chrome_cookies

# Clean up database files for fresh start
echo ""
echo "🗑️  Database status check..."
if [ -f "responses.db" ]; then
    echo -e "${YELLOW}📊 Response database found at responses.db${NC}"
    echo -e "${YELLOW}   Contains chat history and responses${NC}"
    echo -e "${YELLOW}   To reset chat history: rm responses.db${NC}"
    # Uncomment the next line to auto-delete on stop:
    # rm -f responses.db
    # echo -e "${GREEN}✅ Removed responses.db${NC}"
fi

if [ -f "kvstore.db" ]; then
    echo -e "${YELLOW}📊 Key-value store found at kvstore.db${NC}"
    echo -e "${YELLOW}   Contains application state and cache${NC}"
    echo -e "${YELLOW}   To reset app state: rm kvstore.db${NC}"
    # Uncomment the next line to auto-delete on stop:
    # rm -f kvstore.db
    # echo -e "${GREEN}✅ Removed kvstore.db${NC}"
fi

# Clean up any remaining processes
echo ""
echo "🧹 Cleaning up any remaining demo processes..."

# Kill any remaining Python processes that might be part of the demo
REMAINING_PIDS=$(ps aux | grep -E "(mcp_server|chat_app|admin_dashboard)" | grep -v grep | awk '{print $2}')

if [ -n "$REMAINING_PIDS" ]; then
    echo -e "${YELLOW}🔄 Killing remaining demo processes...${NC}"
    echo "$REMAINING_PIDS" | xargs kill -9 2>/dev/null || true
    echo -e "${GREEN}✅ Cleaned up remaining processes${NC}"
fi

# Kill any remaining llama stack processes
LLAMA_PIDS=$(ps aux | grep "llama stack" | grep -v grep | awk '{print $2}')
if [ -n "$LLAMA_PIDS" ]; then
    echo -e "${YELLOW}🔄 Killing remaining Llama Stack processes...${NC}"
    echo "$LLAMA_PIDS" | xargs kill -9 2>/dev/null || true
    echo -e "${GREEN}✅ Cleaned up Llama Stack processes${NC}"
fi

echo ""
echo -e "${GREEN}🎉 All demo services stopped successfully!${NC}"
echo -e "${GREEN}🔐 Keycloak SSO session cleared - you'll need to login again${NC}"
echo ""
echo "📝 Data preserved for next restart:"
echo "├── logs/ - Server logs"
echo "├── responses.db - Chat history (if exists)"
echo "└── kvstore.db - Application state (if exists)"
echo ""
echo -e "${BLUE}🔄 Next steps:${NC}"
echo "   🚀 Restart demo: $SCRIPT_DIR/start_demo.sh"
echo "   🧹 Complete reset: $SCRIPT_DIR/cleanup_demo.sh"
echo "   🛑 Stop Keycloak: $SCRIPT_DIR/stop_keycloak.sh"
echo ""
echo -e "${YELLOW}💡 Tip: This preserves all chat history and application state${NC}"
echo -e "${YELLOW}     Keycloak SSO session has been cleared for clean login${NC}"
echo -e "${YELLOW}     For a fresh start, use $SCRIPT_DIR/cleanup_demo.sh${NC}"