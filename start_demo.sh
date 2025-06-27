#!/bin/bash

# 🚀 Unified Authentication & Authorization Demo Setup Script
# This script starts all required services for the demo

echo "🚀 Starting Unified Authentication & Authorization Demo..."
echo "========================================================"

# Check for required environment variables
echo "🔍 Checking environment variables..."

# Load environment variables from .env file
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Set PROJECT_ROOT for the demo
export PROJECT_ROOT=$(pwd)
export PYTHONPATH="${PROJECT_ROOT}/frontend/auth-agent/src:${PYTHONPATH}"

# Set admin email for the demo
export ADMIN_EMAIL="gallettilance@gmail.com"

# Google OAuth is optional - demo login works without it
if [ -z "$GOOGLE_CLIENT_ID" ]; then
    echo "⚠️  GOOGLE_CLIENT_ID not set - OAuth will be disabled"
    echo "   Demo login will be available at http://localhost:8002/auth/demo-login"
else
    echo "✅ Google OAuth environment variables are set"
    echo "   GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID:0:10}..."
    if [ -n "$GOOGLE_CLIENT_SECRET" ]; then
        echo "   GOOGLE_CLIENT_SECRET: ${GOOGLE_CLIENT_SECRET:0:10}..."
    else
        echo "⚠️  GOOGLE_CLIENT_SECRET not set - OAuth may not work properly"
    fi
fi
echo ""

# Function to check if a service is running on a port
check_port() {
    local port=$1
    local service=$2
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
        echo "⚠️  Port $port is already in use (possibly $service already running)"
        return 1
    else
        return 0
    fi
}

# Function to check if a service is running on a port
check_port() {
    local port=$1
    local service=$2
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
        echo "⚠️  Port $port is already in use (possibly $service already running)"
        return 1
    else
        return 0
    fi
}

# Check if required ports are available (excluding the old approval server port 8002)
echo "🔍 Checking ports..."
ports_to_check=(5001 8002 8001 8321)
services=("Chat App" "Unified Auth Server" "MCP Server" "Llama Stack")

for i in "${!ports_to_check[@]}"; do
    port=${ports_to_check[$i]}
    service=${services[$i]}
    if ! check_port $port "$service"; then
        echo "❌ Port $port is busy. Please stop existing service or change port."
        echo "   Try: lsof -ti:$port | xargs kill -9"
        exit 1
    fi
done

echo "✅ All ports available"
echo ""

# Create log directory first
echo "📁 Creating logs directory..."
mkdir -p logs
if [ ! -d "logs" ]; then
    echo "❌ Failed to create logs directory"
    exit 1
fi
echo "✅ Logs directory ready"
echo ""

echo "🌟 Starting services..."
echo "======================"

# Initialize database and setup admin user
echo "1️⃣  Initializing database and setting up admin user..."
cd auth-server
python init_admin.py --email "$ADMIN_EMAIL" --force
echo ""

# Start Unified Auth Server (Port 8002)
echo "2️⃣  Starting Unified Auth Server on port 8002..."
python unified_auth_server.py > ../logs/unified_auth_server.log 2>&1 &
AUTH_PID=$!
echo "   PID: $AUTH_PID"
cd ..
sleep 2

# Start MCP Server (Port 8001)
echo "3️⃣  Starting MCP Server on port 8001..."
cd mcp
FASTMCP_PORT=8001 python mcp_server.py > ../logs/mcp_server.log 2>&1 &
MCP_PID=$!
echo "   PID: $MCP_PID"
cd ..
sleep 2

# Start Llama Stack (Port 8321)
echo "4️⃣  Starting Llama Stack on port 8321..."
./env/bin/llama stack run frontend/stack/run.yml > logs/llama_stack.log 2>&1 &
LLAMA_PID=$!
echo "   PID: $LLAMA_PID"
sleep 3

# Start Chat App (Port 5001)
echo "5️⃣  Starting Chat App on port 5001..."
cd frontend
python chat_app.py > ../logs/chat_app.log 2>&1 &
CHAT_PID=$!
echo "   PID: $CHAT_PID"
cd ..

# Save PIDs for cleanup
echo "$AUTH_PID $MCP_PID $LLAMA_PID $CHAT_PID" > demo_pids.txt

echo ""
echo "🎉 All services started successfully!"
echo "===================================="
echo ""
echo "📊 Service Status:"
echo "├── 🔐 Unified Auth Server: http://localhost:8002    (PID: $AUTH_PID)"
echo "│   ├── OAuth & JWT Management"
echo "│   ├── Scope-based Authorization"  
echo "│   ├── Approval Workflows"
echo "│   └── Admin Dashboard"
echo "├── 📡 MCP Server:          http://localhost:8001    (PID: $MCP_PID)"
echo "├── 🦙 Llama Stack:         http://localhost:8321    (PID: $LLAMA_PID)"
echo "└── 🌐 Chat App:            http://localhost:5001    (PID: $CHAT_PID)"
echo ""
echo "📝 Logs are being written to the logs/ directory:"
echo "├── logs/unified_auth_server.log"
echo "├── logs/mcp_server.log"
echo "├── logs/llama_stack.log"
echo "└── logs/chat_app.log"
echo ""
echo "🎬 Demo Users:"
echo "├── 👑 Admin:     gallettilance@gmail.com (pre-configured)"
echo "└── 👤 Users:     Auto-created with 'user' role on first login"
echo ""
echo "🔗 Quick Links:"
echo "├── 🏠 Auth Dashboard:  http://localhost:8002/dashboard"
echo "├── 🔑 Demo Login:      http://localhost:8002/auth/demo-login"
echo "└── 💬 Chat Interface:  http://localhost:5001"
echo ""
echo "📖 Follow the steps in DEMO_SHOWCASE.md to run the demo"
echo ""
echo "🛑 To stop all services, run: ./stop_demo.sh"
echo ""

# Wait a moment and check if services are responding
echo "🔍 Checking service health..."
sleep 1

# Function to check if a service is responding
check_service() {
    local url=$1
    local name=$2
    if curl -s "$url" > /dev/null 2>&1; then
        echo "✅ $name is responding"
    else
        echo "⚠️  $name might not be ready yet (check logs for details)"
    fi
}

check_service "http://localhost:8002" "Unified Auth Server"
check_service "http://localhost:8001" "MCP Server"  
check_service "http://localhost:5001" "Chat App"

echo ""
echo "🚀 Unified demo environment is ready!"
echo ""
echo "🎯 Getting Started:"
echo "1. Open the chat app: http://localhost:5001"
echo "2. Login with demo credentials (or set up Google OAuth)"
echo "3. Try commands that require authorization (e.g., 'list files in /tmp')"
echo "4. Experience the approval workflow for restricted operations"
echo "5. Use the admin dashboard to manage approvals: http://localhost:8002/dashboard" 