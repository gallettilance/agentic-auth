#!/bin/bash

# 🧹 Complete Demo Cleanup Script
# Removes all demo data for a fresh start

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🧹 Complete Demo Cleanup${NC}"
echo "================================"
echo ""
echo -e "${YELLOW}⚠️  WARNING: This will delete ALL demo data:${NC}"
echo "   - Database (users, permissions, approvals)"
echo "   - JWT keys (will be regenerated on next start)"
echo "   - Log files"
echo "   - Session data"
echo "   - Browser cookies"
echo ""

# Ask for confirmation
read -p "Are you sure you want to proceed? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}❌ Cleanup cancelled${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}🛑 Stopping all demo services first...${NC}"

# Stop services first
./stop_demo.sh > /dev/null 2>&1 || true

echo ""
echo -e "${BLUE}🗑️  Cleaning up demo artifacts...${NC}"

# Function to safely remove file/directory
safe_remove() {
    local path=$1
    local description=$2
    
    if [ -e "$path" ]; then
        rm -rf "$path"
        echo -e "${GREEN}✅ Removed $description${NC}"
    else
        echo -e "${YELLOW}⚠️  $description not found (already clean)${NC}"
    fi
}

# Clean up databases
echo ""
echo -e "${YELLOW}📊 Database cleanup:${NC}"
safe_remove "auth-server/auth.db" "auth database"
safe_remove "auth.db" "auth database (root)"
safe_remove "responses.db" "responses database"
safe_remove "kvstore.db" "key-value store database"

# Clean up JWT keys
echo ""
echo -e "${YELLOW}🔑 JWT keys cleanup:${NC}"
safe_remove "auth-server/keys/" "JWT keys directory"

# Clean up logs
echo ""
echo -e "${YELLOW}📝 Log files cleanup:${NC}"
safe_remove "logs/" "logs directory"
safe_remove "cookies.txt" "HTTP cookies file"

# Clean up session/cache files
echo ""
echo -e "${YELLOW}💾 Session/cache cleanup:${NC}"
safe_remove "demo_pids.txt" "process IDs file"
safe_remove "__pycache__/" "Python cache (root)"
safe_remove "auth-server/__pycache__/" "Python cache (auth-server)"
safe_remove "frontend/__pycache__/" "Python cache (frontend)"
safe_remove "mcp/__pycache__/" "Python cache (mcp)"
safe_remove "frontend/auth-agent/src/auth_agent/__pycache__/" "Python cache (auth-agent)"

# Clean up Python egg-info
echo ""
echo -e "${YELLOW}🥚 Python package artifacts:${NC}"
safe_remove "frontend/auth-agent/src/auth_agent.egg-info/" "auth-agent egg-info"

# Clean up any .pyc files
echo ""
echo -e "${YELLOW}🐍 Python bytecode cleanup:${NC}"
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "*.pyo" -delete 2>/dev/null || true
find . -name "*.pyd" -delete 2>/dev/null || true
echo -e "${GREEN}✅ Removed Python bytecode files${NC}"

# Clean up environment-specific files
echo ""
echo -e "${YELLOW}🌍 Environment cleanup:${NC}"
safe_remove ".env.local" "local environment file"

# Chrome cookies cleanup
echo ""
echo -e "${YELLOW}🍪 Browser cookies cleanup:${NC}"

cleanup_chrome_cookies() {
    # Force quit Chrome first
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
    fi
}

cleanup_chrome_cookies

# Clean up any remaining demo processes
echo ""
echo -e "${YELLOW}⚡ Process cleanup:${NC}"
REMAINING_PIDS=$(ps aux | grep -E "(auth_server|unified_auth_server|mcp_server|chat_app)" | grep -v grep | awk '{print $2}' || true)

if [ -n "$REMAINING_PIDS" ]; then
    echo -e "${YELLOW}🔄 Killing remaining demo processes...${NC}"
    echo "$REMAINING_PIDS" | xargs kill -9 2>/dev/null || true
    echo -e "${GREEN}✅ Cleaned up remaining processes${NC}"
else
    echo -e "${GREEN}✅ No demo processes running${NC}"
fi

# Verify cleanup
echo ""
echo -e "${BLUE}🔍 Cleanup verification:${NC}"

verify_clean() {
    local path=$1
    local name=$2
    
    if [ -e "$path" ]; then
        echo -e "${RED}❌ $name still exists: $path${NC}"
        return 1
    else
        echo -e "${GREEN}✅ $name cleaned${NC}"
        return 0
    fi
}

verify_clean "auth-server/auth.db" "Auth database"
verify_clean "auth-server/keys/" "JWT keys"
verify_clean "logs/" "Log files"
verify_clean "demo_pids.txt" "PID file"

echo ""
echo -e "${GREEN}🎉 Demo cleanup completed successfully!${NC}"
echo ""
echo -e "${BLUE}📋 What was cleaned:${NC}"
echo "   ✅ All databases (users, permissions, sessions)"
echo "   ✅ JWT keys (will be auto-generated on next start)"
echo "   ✅ Log files and session data"
echo "   ✅ Python cache and bytecode"
echo "   ✅ Browser cookies for localhost"
echo "   ✅ Background processes"
echo ""
echo -e "${GREEN}🚀 Ready for a fresh demo start!${NC}"
echo "   Run: ${BLUE}./start_demo.sh${NC}"
echo ""
echo -e "${YELLOW}💡 Tip: Use ./stop_demo.sh for normal shutdown (preserves data)${NC}"
echo -e "${YELLOW}     Use ./cleanup_demo.sh for complete reset (removes everything)${NC}" 