#!/bin/bash

# Enhanced Auth System Demo Startup Script
# Supports both symmetric and asymmetric JWT modes

set -e

echo "🚀 Starting Enhanced Authentication System Demo..."

# Load environment variables from .env file if it exists
if [ -f ".env" ]; then
    echo "📋 Loading environment variables from .env file..."
    export $(grep -v '^#' .env | xargs)
fi

# Configuration
export SERVER_HOST=${SERVER_HOST:-localhost}
export SERVER_PORT=${SERVER_PORT:-8002}
export MCP_SERVER_URI=${MCP_SERVER_URI:-http://localhost:8001}
export AUTH_DB_PATH=${AUTH_DB_PATH:-auth.db}
export KUBERNETES_MCP_SERVER_DIR=${KUBERNETES_MCP_SERVER_DIR:-}

# Admin Configuration
export ADMIN_EMAIL=${ADMIN_EMAIL:-gallettilance@gmail.com}

# JWT Configuration
export JWT_MODE=${JWT_MODE:-asymmetric}  # "symmetric" or "asymmetric"
export JWT_SECRET=${JWT_SECRET:-demo-secret-key-change-in-production}

if [ "$JWT_MODE" = "asymmetric" ]; then
    export PRIVATE_KEY_PATH=${PRIVATE_KEY_PATH:-keys/private_key.pem}
    export JWKS_PATH=${JWKS_PATH:-keys/jwks.json}
    echo "🔑 JWT Mode: Asymmetric (RS256)"
    echo "   - Private key: $PRIVATE_KEY_PATH"
    echo "   - JWKS: $JWKS_PATH"
    echo "   - Keys will be auto-generated if not found"
else
    echo "🔑 JWT Mode: Symmetric (HS256)"
    echo "   - Secret: ${JWT_SECRET:0:20}..."
fi

# OAuth Configuration
export OIDC_CLIENT_ID=${OIDC_CLIENT_ID:-}
export OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET:-}

echo ""
echo "📋 Configuration:"
echo "   - Auth Server: http://$SERVER_HOST:$SERVER_PORT"
echo "   - MCP Server: $MCP_SERVER_URI"
echo "   - Database: $AUTH_DB_PATH"
echo "   - JWT Mode: $JWT_MODE"
echo "   - Admin Email: $ADMIN_EMAIL"

# Create logs directory
mkdir -p logs

# Function to cleanup background processes
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."
    
    # Kill background processes
    if [ ! -z "$AUTH_PID" ]; then
        kill $AUTH_PID 2>/dev/null || true
        echo "   ✅ Auth server stopped"
    fi
    
    if [ ! -z "$ADMIN_PID" ]; then
        kill $ADMIN_PID 2>/dev/null || true
        echo "   ✅ Admin dashboard stopped"
    fi
    
    if [ ! -z "$MCP_PID" ]; then
        kill $MCP_PID 2>/dev/null || true
        echo "   ✅ MCP server stopped"
    fi
    
    if [ ! -z "$LLAMA_PID" ]; then
        kill $LLAMA_PID 2>/dev/null || true
        echo "   ✅ Llama Stack stopped"
    fi
    
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null || true
        echo "   ✅ Frontend stopped"
    fi
    
    # Clean up temporary kubernetes-mcp-server directory if we created one
    if [ -n "$KMCP_DIR" ] && [ -z "$KUBERNETES_MCP_SERVER_DIR" ] && [ -d "$KMCP_DIR" ]; then
        echo "   🧹 Cleaning up temporary kubernetes-mcp-server directory: $KMCP_DIR"
        rm -rf "$KMCP_DIR"
        echo "   ✅ Temporary directory cleaned up"
    fi
    
    echo "🏁 Demo stopped"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Generate keys if using asymmetric mode
if [ "$JWT_MODE" = "asymmetric" ]; then
    echo ""
    echo "🔑 Setting up asymmetric JWT keys..."
    cd auth-server
    if [ ! -f "keys/private_key.pem" ] || [ ! -f "keys/jwks.json" ]; then
        echo "   📝 Generating RSA key pair..."
        python generate_keys.py
    else
        echo "   ✅ Keys already exist"
    fi
    cd ..
fi

# Start Auth Server (Refactored)
echo ""
echo "🔐 Starting Auth Server..."
cd auth-server
python main.py > ../logs/auth_server.log 2>&1 &
AUTH_PID=$!
cd ..
echo "   ✅ Auth Server started (PID: $AUTH_PID)"
echo "   📝 Logs: logs/auth_server.log"

# Wait a moment for auth server to start
sleep 3

# Start Admin Dashboard Frontend
echo ""
echo "🎛️ Starting Admin Dashboard Frontend..."
cd frontends/admin-dashboard
python app.py > ../../logs/admin_dashboard.log 2>&1 &
ADMIN_PID=$!
cd ../..
echo "   ✅ Admin Dashboard started (PID: $ADMIN_PID)"
echo "   📝 Logs: logs/admin_dashboard.log"

# Wait a moment for admin dashboard to start
sleep 2

# Start Llama Stack
echo ""
echo "🦙 Starting Llama Stack..."
llama stack run services/stack/run.yml > logs/llama_stack.log 2>&1 &
LLAMA_PID=$!
echo "   ✅ Llama Stack started (PID: $LLAMA_PID)"
echo "   📝 Logs: logs/llama_stack.log"

# Wait a moment for Llama Stack to start
sleep 3

# Start Frontend
echo ""
echo "🌐 Starting Frontend..."
cd frontends/chat-ui
python app.py > ../../logs/frontend.log 2>&1 &
FRONTEND_PID=$!
cd ../..
echo "   ✅ Frontend started (PID: $FRONTEND_PID)"
echo "   📝 Logs: logs/frontend.log"

# Wait a moment for everything to start
sleep 2

# Start MCP Server
echo ""
echo "🔧 Starting Kubernetes MCP Server..."

# Check if user specified a directory for kubernetes-mcp-server
if [ -n "$KUBERNETES_MCP_SERVER_DIR" ] && [ -d "$KUBERNETES_MCP_SERVER_DIR" ]; then
    echo "   📁 Using existing kubernetes-mcp-server directory: $KUBERNETES_MCP_SERVER_DIR"
    KMCP_DIR="$KUBERNETES_MCP_SERVER_DIR"
else
    # Clone to temporary directory
    KMCP_DIR=$(mktemp -d)
    echo "   📦 Cloning kubernetes-mcp-server to temporary directory: $KMCP_DIR"
    git clone https://github.com/containers/kubernetes-mcp-server.git "$KMCP_DIR"
fi

# Build the kubernetes-mcp-server
echo "   🔨 Building kubernetes-mcp-server..."
pushd "$KMCP_DIR"
go build -o kubernetes-mcp-server ./cmd/kubernetes-mcp-server
echo "   ✅ Build completed"
popd

# Run the kubernetes-mcp-server with our config
echo "   🚀 Starting kubernetes-mcp-server with mcp_config.toml..."
"$KMCP_DIR/kubernetes-mcp-server" --config "$(pwd)/mcp_config.toml" > logs/mcp_server.log 2>&1 &
MCP_PID=$!
cd ..
echo "   ✅ MCP Server started (PID: $MCP_PID)"
echo "   📝 Logs: logs/mcp_server.log"

# Wait a moment for MCP server to start
sleep 2

echo ""
echo "🎉 Demo is ready!"
echo ""
echo "📱 Access Points:"
echo "   🌐 Chat Frontend: http://localhost:5001"
echo "   🎛️ Admin Dashboard: http://localhost:8003"
echo "   🔐 Auth Server: http://$SERVER_HOST:$SERVER_PORT"
echo "   🔧 MCP Server: $MCP_SERVER_URI"
echo "   🦙 Llama Stack: http://localhost:8321"
echo ""

if [ "$JWT_MODE" = "asymmetric" ]; then
    echo "🔑 JWT Endpoints:"
    echo "   📋 JWKS: http://$SERVER_HOST:$SERVER_PORT/.well-known/jwks.json"
    echo "   📋 OAuth Metadata: http://$SERVER_HOST:$SERVER_PORT/.well-known/oauth-authorization-server"
    echo ""
fi

echo "📊 Monitoring:"
echo "   📝 Auth Server Logs: tail -f logs/auth_server.log"
echo "   📝 Admin Dashboard Logs: tail -f logs/admin_dashboard.log"
echo "   📝 MCP Server Logs: tail -f logs/mcp_server.log"
echo "   📝 Llama Stack Logs: tail -f logs/llama_stack.log"
echo "   📝 Frontend Logs: tail -f logs/frontend.log"
echo ""
echo "🛑 To stop: Ctrl+C or run ./stop_demo.sh"
echo ""

echo "🎯 Demo Features:"
echo "   • OpenID Connect (OIDC) integration"
echo "   • Database-backed user and permission management"
echo "   • JWT token generation and validation"
echo "   • MCP tool integration with scope-based authorization"
echo "   • Real-time approval workflows for privileged operations"
echo "   • Interactive chat interface with Llama Stack agents"
echo ""
echo "🔐 Security Enhancements (NEW):"
echo "   • Enhanced Protected Resource Metadata (RFC 9728)"
echo "   • Resource Parameter Validation (RFC 8707)"
echo "   • MCP Server URI Validation & Typosquatting Detection"
echo "   • Domain Verification Support"
echo "   • Auth Server Consistency Verification"
echo "   • Enhanced Security Warnings & User Notifications"
echo ""

# Wait for user interruption
wait 