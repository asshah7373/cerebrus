#!/bin/bash

# Cerebrus AI Pentesting Tool - Run Script
# Starts both backend and frontend in development mode

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Starting Cerebrus AI Pentesting Tool..."
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Running setup..."
    ./scripts/setup.sh
fi

# Activate virtual environment
source venv/bin/activate

# Check for .env file
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Warning: .env file not found. Creating default...${NC}"
    cp .env.example .env 2>/dev/null || echo "Please create .env file manually"
fi

# Start backend in background
echo "Starting backend server..."
python -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!

# Wait for backend to start
sleep 3

# Check if backend is running
if ! kill -0 $BACKEND_PID 2>/dev/null; then
    echo "Failed to start backend server"
    exit 1
fi

echo -e "${GREEN}✓ Backend running on http://127.0.0.1:8000${NC}"

# Start frontend
echo "Starting frontend server..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

# Wait for frontend to start
sleep 3

echo -e "${GREEN}✓ Frontend running on http://127.0.0.1:3000${NC}"
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Cerebrus is running!                                       ║"
echo "║  Open http://localhost:3000 in your browser                 ║"
echo "║  Press Ctrl+C to stop                                       ║"
echo "╚════════════════════════════════════════════════════════════╝"

# Handle shutdown
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" SIGINT SIGTERM

# Wait for processes
wait
