#!/bin/bash

# 🛑 Stop Unified Authentication & Authorization Demo Services

echo "🛑 Stopping Unified Authentication & Authorization Demo..."
echo "========================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
    read AUTH_PID MCP_PID LLAMA_PID CHAT_PID < demo_pids.txt
    
    # Stop services by PID
    stop_by_pid "$CHAT_PID" "Chat App"
    stop_by_pid "$LLAMA_PID" "Llama Stack"
    stop_by_pid "$MCP_PID" "MCP Server"
    stop_by_pid "$AUTH_PID" "Unified Auth Server"
    
    # Remove PID file
    rm -f demo_pids.txt
    echo "🗑️  Removed demo_pids.txt"
else
    echo "⚠️  demo_pids.txt not found, stopping by port..."
fi

# Stop services by port (backup method)
echo ""
echo "🔍 Checking ports for any remaining processes..."
stop_by_port 5001 "Chat App"
stop_by_port 8321 "Llama Stack"
stop_by_port 8001 "MCP Server"
stop_by_port 8002 "Unified Auth Server"

# Note: Port 8002 is used by Unified Auth Server (already stopped above)

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
    
    # Clear Chrome localhost cookies
    if [ -f "$CHROME_COOKIES" ] && command -v sqlite3 >/dev/null 2>&1; then
        echo -e "${YELLOW}🔄 Clearing Chrome localhost cookies...${NC}"
        sqlite3 "$CHROME_COOKIES" "DELETE FROM cookies WHERE host_key LIKE '%localhost%' OR host_key LIKE '%.localhost%';" 2>/dev/null || true
        echo -e "${GREEN}✅ Chrome localhost cookies cleared${NC}"
    else
        echo -e "${YELLOW}⚠️  Chrome cookies database not found or sqlite3 not available${NC}"
        echo -e "${YELLOW}   Chrome may not be installed or cookies are in a different location${NC}"
    fi
}

cleanup_chrome_cookies

# Clean up database files for fresh start
echo ""
echo "🗑️  Cleaning up database files..."
if [ -f "responses.db" ]; then
    rm -f responses.db
    echo -e "${GREEN}✅ Removed responses.db${NC}"
fi

if [ -f "kvstore.db" ]; then
    rm -f kvstore.db
    echo -e "${GREEN}✅ Removed kvstore.db${NC}"
fi

# Clean up auth database
if [ -f "auth-server/auth.db" ]; then
    rm -f auth-server/auth.db
    echo -e "${GREEN}✅ Removed auth-server/auth.db${NC}"
fi

# Clean up any remaining processes
echo ""
echo "🧹 Cleaning up any remaining demo processes..."

# Kill any remaining Python processes that might be part of the demo
REMAINING_PIDS=$(ps aux | grep -E "(auth_server|approval_server|unified_auth_server|mcp_server|auth_mcp_server|chat_app)" | grep -v grep | awk '{print $2}')

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
echo ""
echo "📝 Log files are preserved in the logs/ directory:"
echo "├── logs/unified_auth_server.log"
echo "├── logs/mcp_server.log"
echo "├── logs/llama_stack.log"
echo "└── logs/chat_app.log"
echo ""
echo "🚀 To restart the demo, run: ./start_demo.sh" 