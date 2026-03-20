#!/bin/bash

# AI-NDR Platform Deployment Script for roahacks.com
# Usage: ./deploy.sh [setup|start|stop|restart|logs]

set -e

DOMAIN="roahacks.com"
EMAIL="admin@roahacks.com"  # Change this to your email
ENVIRONMENT=${1:-start}

echo "🚀 AI-NDR Platform Deployment - $DOMAIN"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if .env exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚠️  .env file not found. Creating from .env.example${NC}"
    cp .env.example .env
    echo -e "${RED}❌ Please edit .env with your configuration and run again${NC}"
    exit 1
fi

# Function: Setup SSL certificates
setup_ssl() {
    echo -e "${YELLOW}🔒 Setting up SSL certificates with Let's Encrypt${NC}"

    # Install certbot if not present
    if ! command -v certbot &> /dev/null; then
        echo "Installing certbot..."
        sudo apt-get update
        sudo apt-get install -y certbot python3-certbot-nginx
    fi

    # Create certificate for roahacks.com and subdomains
    sudo certbot certonly --standalone \
        -d roahacks.com \
        -d www.roahacks.com \
        -d api.roahacks.com \
        -d app.roahacks.com \
        -m $EMAIL \
        --agree-tos \
        --non-interactive \
        --preferred-challenges http

    echo -e "${GREEN}✅ SSL certificates installed${NC}"
}

# Function: Setup Nginx
setup_nginx() {
    echo -e "${YELLOW}🌐 Setting up Nginx${NC}"

    # Copy config to sites-available
    sudo cp nginx.conf.prod /etc/nginx/sites-available/roahacks.com

    # Enable site
    sudo ln -sf /etc/nginx/sites-available/roahacks.com /etc/nginx/sites-enabled/roahacks.com

    # Remove default
    sudo rm -f /etc/nginx/sites-enabled/default

    # Test config
    sudo nginx -t

    # Reload nginx
    sudo systemctl reload nginx

    echo -e "${GREEN}✅ Nginx configured${NC}"
}

# Function: Setup system
setup_system() {
    echo -e "${YELLOW}📦 Setting up system${NC}"

    # Install Docker if not present
    if ! command -v docker &> /dev/null; then
        echo "Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo usermod -aG docker $USER
    fi

    # Install Docker Compose if not present
    if ! command -v docker-compose &> /dev/null; then
        echo "Installing Docker Compose..."
        sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
    fi

    # Create backup directory
    mkdir -p db_backup

    echo -e "${GREEN}✅ System setup complete${NC}"
}

# Function: Build and start services
start_services() {
    echo -e "${YELLOW}🐳 Building and starting Docker containers${NC}"

    # Build images
    docker-compose -f docker-compose.prod.yml build

    # Start services
    docker-compose -f docker-compose.prod.yml up -d

    # Wait for services to be healthy
    echo "Waiting for services to become healthy..."
    sleep 10

    # Check health
    docker-compose -f docker-compose.prod.yml ps

    echo -e "${GREEN}✅ Services started${NC}"
}

# Function: Stop services
stop_services() {
    echo -e "${YELLOW}⏹️  Stopping services${NC}"
    docker-compose -f docker-compose.prod.yml down
    echo -e "${GREEN}✅ Services stopped${NC}"
}

# Function: Restart services
restart_services() {
    echo -e "${YELLOW}🔄 Restarting services${NC}"
    docker-compose -f docker-compose.prod.yml restart
    echo -e "${GREEN}✅ Services restarted${NC}"
}

# Function: Show logs
show_logs() {
    echo -e "${YELLOW}📋 Showing logs (Press Ctrl+C to exit)${NC}"
    docker-compose -f docker-compose.prod.yml logs -f
}

# Function: Setup SSL auto-renewal
setup_ssl_renewal() {
    echo -e "${YELLOW}🔄 Setting up SSL auto-renewal${NC}"

    # Create renewal script
    cat > /etc/cron.d/certbot-renewal << EOF
0 0 * * * root certbot renew --quiet --post-hook "systemctl reload nginx"
EOF

    echo -e "${GREEN}✅ SSL auto-renewal configured${NC}"
}

# Function: Full setup (everything)
full_setup() {
    echo -e "${YELLOW}🛠️  Running full setup${NC}"
    setup_system
    setup_ssl
    setup_ssl_renewal
    setup_nginx
    start_services

    echo -e "${GREEN}✅ Full setup complete!${NC}"
    echo ""
    echo "🎉 Your platform is now live at:"
    echo "  • Frontend: https://app.roahacks.com"
    echo "  • API: https://api.roahacks.com"
    echo "  • Metrics: https://api.roahacks.com/metrics"
    echo ""
    echo "📊 Monitor with: docker-compose -f docker-compose.prod.yml logs -f"
}

# Main logic
case $ENVIRONMENT in
    setup)
        full_setup
        ;;
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    logs)
        show_logs
        ;;
    *)
        echo "Usage: $0 [setup|start|stop|restart|logs]"
        echo ""
        echo "Commands:"
        echo "  setup   - Full setup (system, SSL, Nginx, Docker)"
        echo "  start   - Start services"
        echo "  stop    - Stop services"
        echo "  restart - Restart services"
        echo "  logs    - Show logs"
        exit 1
        ;;
esac
