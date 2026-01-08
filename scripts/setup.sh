#!/bin/bash

# Cerebrus AI Pentesting Tool - Setup Script
# This script sets up the development environment

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║           Cerebrus AI Pentesting Tool Setup                 ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}Warning: Running as root is not recommended for development${NC}"
fi

# Check Python version
echo "Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d" " -f2)
    echo -e "${GREEN}✓ Python ${PYTHON_VERSION} found${NC}"
else
    echo -e "${RED}✗ Python 3 not found. Please install Python 3.10+${NC}"
    exit 1
fi

# Check Node.js version
echo "Checking Node.js version..."
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo -e "${GREEN}✓ Node.js ${NODE_VERSION} found${NC}"
else
    echo -e "${RED}✗ Node.js not found. Please install Node.js 18+${NC}"
    exit 1
fi

# Create virtual environment
echo ""
echo "Creating Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${YELLOW}! Virtual environment already exists${NC}"
fi

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
echo -e "${GREEN}✓ Python dependencies installed${NC}"

# Install frontend dependencies
echo ""
echo "Installing frontend dependencies..."
cd frontend
npm install
cd ..
echo -e "${GREEN}✓ Frontend dependencies installed${NC}"

# Create necessary directories
echo ""
echo "Creating directories..."
mkdir -p logs data reports exports
echo -e "${GREEN}✓ Directories created${NC}"

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo ""
    echo "Creating .env file..."
    cat > .env << EOF
# Cerebrus Configuration
# Add your API keys here

# AI Provider (required for AI features)
ANTHROPIC_API_KEY=your_anthropic_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# Database
DATABASE_URL=sqlite+aiosqlite:///./data/cerebrus.db

# Server
HOST=127.0.0.1
PORT=8000
DEBUG=true

# Security
AUTOMATION_LEVEL=semi_auto
MAX_RISK_AUTO=low
REQUIRE_AUTHORIZATION=true

# Logging
LOG_LEVEL=INFO
EOF
    echo -e "${GREEN}✓ .env file created${NC}"
    echo -e "${YELLOW}! Please edit .env and add your API keys${NC}"
else
    echo -e "${YELLOW}! .env file already exists${NC}"
fi

# Initialize database
echo ""
echo "Initializing database..."
python3 -c "
import asyncio
from backend.models.database import init_db
asyncio.run(init_db())
print('Database initialized')
"
echo -e "${GREEN}✓ Database initialized${NC}"

# Check for Kali tools
echo ""
echo "Checking for pentesting tools..."
TOOLS=("nmap" "nikto" "hydra" "gobuster" "sqlmap")
MISSING_TOOLS=()

for tool in "${TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        echo -e "${GREEN}✓ $tool found${NC}"
    else
        echo -e "${YELLOW}! $tool not found${NC}"
        MISSING_TOOLS+=($tool)
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}Some pentesting tools are missing. Install them with:${NC}"
    echo "  sudo apt-get install ${MISSING_TOOLS[*]}"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete!                          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "To start the development server:"
echo ""
echo "  1. Activate the virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Start the backend:"
echo "     python -m uvicorn backend.api.main:app --reload"
echo ""
echo "  3. In another terminal, start the frontend:"
echo "     cd frontend && npm run dev"
echo ""
echo "  4. Open http://localhost:3000 in your browser"
echo ""
