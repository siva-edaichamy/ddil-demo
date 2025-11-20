#!/bin/bash

# Docker deployment helper script for DDIL Demo

set -e

echo "🐳 DDIL Demo Docker Deployment"
echo "================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
mkdir -p config logs

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from example..."
    cat > .env << EOF
# Postgres Configuration (for latency check)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=postgres
POSTGRES_USER=postgres
POSTGRES_PASSWORD=

# Demo Dashboard URL
DEMO_DASHBOARD_URL=http://localhost:5002
EOF
    echo "✅ Created .env file. Please update it with your configuration."
fi

# Parse command line arguments
COMMAND=${1:-up}

case $COMMAND in
    build)
        echo "🔨 Building Docker image..."
        docker-compose build
        ;;
    up)
        echo "🚀 Starting containers..."
        docker-compose up -d
        echo ""
        echo "✅ Containers started!"
        echo ""
        echo "📊 Access the dashboards:"
        echo "   Control Dashboard: http://localhost:5004"
        echo "   Demo Dashboard: http://localhost:5002"
        echo ""
        echo "📝 View logs: docker-compose logs -f"
        ;;
    down)
        echo "🛑 Stopping containers..."
        docker-compose down
        ;;
    logs)
        echo "📋 Showing logs..."
        docker-compose logs -f
        ;;
    restart)
        echo "🔄 Restarting containers..."
        docker-compose restart
        ;;
    shell)
        echo "🐚 Opening shell in container..."
        docker-compose exec ddil-demo /bin/bash
        ;;
    *)
        echo "Usage: $0 {build|up|down|logs|restart|shell}"
        echo ""
        echo "Commands:"
        echo "  build    - Build the Docker image"
        echo "  up       - Start the containers (default)"
        echo "  down     - Stop the containers"
        echo "  logs     - View container logs"
        echo "  restart  - Restart the containers"
        echo "  shell    - Open a shell in the container"
        exit 1
        ;;
esac

