#!/bin/bash

set -e
set -o pipefail

# Script: docker-langflow.sh
# Purpose: Deploy Langflow using Docker for development and production
# Usage: ./docker-langflow.sh [command] [options]

# Default values
DEFAULT_PORT="7860"
DEFAULT_HOST="0.0.0.0"
DOCKER_IMAGE="langflowai/langflow:latest"
CONTAINER_NAME="langflow"
NETWORK_NAME="langflow-network"
VOLUME_NAME="langflow-data"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Show usage information
show_usage() {
    echo "Usage: ./docker-langflow.sh [command] [options]"
    echo ""
    echo "Commands:"
    echo "  run        - Run Langflow with Docker Compose (uses docker-compose.yml)"
    echo "  start      - Start existing Langflow services"
    echo "  stop       - Stop Langflow services"
    echo "  restart    - Restart Langflow services"
    echo "  logs       - Show service logs"
    echo "  status     - Show service status"
    echo "  shell      - Access Langflow container shell"
    echo "  build      - Build custom Langflow image"
    echo "  deploy     - Deploy with Docker Compose (same as run)"
    echo "  clean      - Clean up containers, images, and volumes"
    echo "  update     - Pull latest images and restart"
    echo "  backup     - Backup Langflow data"
    echo "  restore    - Restore Langflow data"
    echo "  help       - Show this help message"
    echo ""
    echo "Options:"
    echo "  --compose-file FILE - Set Docker Compose file (default: docker-compose.yml)"
    echo "  --env-file FILE     - Set environment file"
    echo "  --detach            - Run in background"
    echo "  --no-pull           - Don't pull latest images"
    echo ""
    echo "Note: Port, host, and other settings are now configured in docker-compose.yml"
    echo ""
    echo "Examples:"
    echo "  ./docker-langflow.sh run"
    echo "  ./docker-langflow.sh run --detach"
    echo "  ./docker-langflow.sh run --env-file langflow.env"
    echo "  ./docker-langflow.sh deploy --compose-file docker-compose.prod.yml"
    echo "  ./docker-langflow.sh update"
    echo ""
    echo "Environment Variables:"
    echo "  LANGFLOW_HOST      - Host to bind to (default: $DEFAULT_HOST)"
    echo "  LANGFLOW_PORT      - Port to bind to (default: $DEFAULT_PORT)"
    echo "  LANGFLOW_DATABASE_URL - Database connection string"
    echo "  LANGFLOW_ENABLE_ANALYTICS - Enable analytics (true/false)"
}

# Check if required tools are available
check_requirements() {
    print_info "Checking requirements..."

    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi

    # Check if Docker daemon is running
    if ! docker info &>/dev/null; then
        print_error "Docker daemon is not running. Please start Docker and try again."
        exit 1
    fi

    # Check if Docker Compose is available
    COMPOSE_CMD="docker compose"
    if ! docker compose version &> /dev/null; then
        if command -v docker-compose &> /dev/null; then
            COMPOSE_CMD="docker-compose"
        else
            print_warning "Docker Compose is not available (deploy command will not work)"
        fi
    fi

    print_success "Docker requirements met"
    echo "$COMPOSE_CMD"
}

# Get Docker Compose command
get_compose_cmd() {
    if docker compose version &> /dev/null; then
        echo "docker compose"
    else
        echo "docker-compose"
    fi
}

# Create Docker network
create_network() {
    local network_name="$1"
    
    if ! docker network ls | grep -q "$network_name"; then
        print_info "Creating Docker network: $network_name"
        docker network create "$network_name"
        print_success "Network created: $network_name"
    else
        print_info "Network already exists: $network_name"
    fi
}

# Pull latest image
pull_image() {
    local image="$1"
    local no_pull="$2"
    
    if [ "$no_pull" != "true" ]; then
        print_info "Pulling latest image: $image"
        docker pull "$image"
        print_success "Image pulled successfully"
    else
        print_info "Skipping image pull (--no-pull specified)"
    fi
}

# Run Langflow container using Docker Compose
run_container() {
    local compose_file="docker-compose.yml"
    local env_file=""
    local detach=false
    local no_pull=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compose-file)
                compose_file="$2"
                shift 2
                ;;
            --env-file)
                env_file="$2"
                shift 2
                ;;
            --detach)
                detach=true
                shift
                ;;
            --no-pull)
                no_pull=true
                shift
                ;;
            # Legacy options for compatibility (ignored when using compose)
            --port|--host|--name|--image|--volume|--network)
                print_warning "Option $1 is ignored when using Docker Compose"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    if [ ! -f "$compose_file" ]; then
        print_error "Docker Compose file not found: $compose_file"
        print_info "Creating default docker-compose.yml..."
        create_default_compose_file "$compose_file"
    fi

    COMPOSE_CMD=$(get_compose_cmd)
    
    # Pull latest images if not disabled
    if [ "$no_pull" != "true" ]; then
        print_info "Pulling latest images..."
        $COMPOSE_CMD pull
    fi
    
    print_info "Starting Langflow with Docker Compose..."
    print_info "Compose file: $compose_file"
    
    if [ -n "$env_file" ] && [ -f "$env_file" ]; then
        print_info "Using environment file: $env_file"
        if [ "$detach" = true ]; then
            $COMPOSE_CMD --env-file "$env_file" up -d
        else
            $COMPOSE_CMD --env-file "$env_file" up
        fi
    else
        if [ "$detach" = true ]; then
            $COMPOSE_CMD up -d
        else
            $COMPOSE_CMD up
        fi
    fi
    
    if [ "$detach" = true ]; then
        print_success "Services started successfully"
        print_info "Use 'docker-langflow.sh logs' to view logs"
        print_info "Use 'docker-langflow.sh status' to check status"
    fi
}

# Start existing services
start_container() {
    local compose_file="docker-compose.yml"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compose-file)
                compose_file="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    if [ ! -f "$compose_file" ]; then
        print_error "Docker Compose file not found: $compose_file"
        exit 1
    fi

    COMPOSE_CMD=$(get_compose_cmd)
    print_info "Starting Langflow services..."
    $COMPOSE_CMD -f "$compose_file" start
    print_success "Services started"
}

# Stop services
stop_container() {
    local compose_file="docker-compose.yml"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compose-file)
                compose_file="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    if [ ! -f "$compose_file" ]; then
        print_error "Docker Compose file not found: $compose_file"
        exit 1
    fi

    COMPOSE_CMD=$(get_compose_cmd)
    print_info "Stopping Langflow services..."
    $COMPOSE_CMD -f "$compose_file" stop
    print_success "Services stopped"
}

# Restart services
restart_container() {
    local compose_file="docker-compose.yml"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compose-file)
                compose_file="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    if [ ! -f "$compose_file" ]; then
        print_error "Docker Compose file not found: $compose_file"
        exit 1
    fi

    COMPOSE_CMD=$(get_compose_cmd)
    print_info "Restarting Langflow services..."
    $COMPOSE_CMD -f "$compose_file" restart
    print_success "Services restarted"
}

# Show service logs
show_logs() {
    local compose_file="docker-compose.yml"
    local follow=false
    local service=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compose-file)
                compose_file="$2"
                shift 2
                ;;
            --service)
                service="$2"
                shift 2
                ;;
            --follow|-f)
                follow=true
                shift
                ;;
            *)
                shift
                ;;
        esac
    done

    if [ ! -f "$compose_file" ]; then
        print_error "Docker Compose file not found: $compose_file"
        exit 1
    fi

    COMPOSE_CMD=$(get_compose_cmd)
    
    if [ -n "$service" ]; then
        print_info "Showing logs for service: $service"
        if [ "$follow" = true ]; then
            $COMPOSE_CMD -f "$compose_file" logs -f "$service"
        else
            $COMPOSE_CMD -f "$compose_file" logs --tail 50 "$service"
        fi
    else
        print_info "Showing logs for all services"
        if [ "$follow" = true ]; then
            $COMPOSE_CMD -f "$compose_file" logs -f
        else
            $COMPOSE_CMD -f "$compose_file" logs --tail 50
        fi
    fi
}

# Show service status
show_status() {
    local compose_file="docker-compose.yml"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compose-file)
                compose_file="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    if [ ! -f "$compose_file" ]; then
        print_error "Docker Compose file not found: $compose_file"
        exit 1
    fi

    COMPOSE_CMD=$(get_compose_cmd)
    
    print_info "Service status:"
    $COMPOSE_CMD -f "$compose_file" ps
    
    echo ""
    print_info "Network status:"
    docker network ls --filter "name=langflow"
    
    echo ""
    print_info "Volume status:"
    docker volume ls --filter "name=langflow"
    
    echo ""
    print_info "Port usage:"
    if command -v lsof &> /dev/null; then
        lsof -i ":7860" 2>/dev/null || print_info "Port 7860 is free"
    fi
}

# Access container shell
access_shell() {
    local compose_file="docker-compose.yml"
    local service="langflow"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compose-file)
                compose_file="$2"
                shift 2
                ;;
            --service)
                service="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    if [ ! -f "$compose_file" ]; then
        print_error "Docker Compose file not found: $compose_file"
        exit 1
    fi

    COMPOSE_CMD=$(get_compose_cmd)
    
    # Check if service is running
    if $COMPOSE_CMD -f "$compose_file" ps -q "$service" | grep -q .; then
        print_info "Accessing shell for service: $service"
        $COMPOSE_CMD -f "$compose_file" exec "$service" /bin/bash
    else
        print_error "Service not running: $service"
        exit 1
    fi
}

# Build custom image
build_image() {
    local dockerfile="Dockerfile"
    local tag="langflow:custom"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dockerfile)
                dockerfile="$2"
                shift 2
                ;;
            --tag)
                tag="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    if [ ! -f "$dockerfile" ]; then
        print_error "Dockerfile not found: $dockerfile"
        exit 1
    fi

    print_info "Building custom image: $tag"
    docker build -t "$tag" -f "$dockerfile" .
    print_success "Image built successfully: $tag"
}

# Deploy with Docker Compose
deploy_compose() {
    local compose_file="docker-compose.yml"
    local env_file=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compose-file)
                compose_file="$2"
                shift 2
                ;;
            --env-file)
                env_file="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    if [ ! -f "$compose_file" ]; then
        print_error "Docker Compose file not found: $compose_file"
        print_info "Creating default docker-compose.yml..."
        create_default_compose_file "$compose_file"
    fi

    COMPOSE_CMD=$(get_compose_cmd)
    
    print_info "Deploying with Docker Compose..."
    
    if [ -n "$env_file" ] && [ -f "$env_file" ]; then
        print_info "Using environment file: $env_file"
        $COMPOSE_CMD --env-file "$env_file" up -d
    else
        $COMPOSE_CMD up -d
    fi
    
    print_success "Deployment completed"
    print_info "Use '$COMPOSE_CMD logs -f' to view logs"
}

# Create default Docker Compose file
create_default_compose_file() {
    local compose_file="$1"
    
    cat > "$compose_file" << 'EOF'
version: '3.8'

services:
  langflow:
    image: langflowai/langflow:latest
    container_name: langflow
    ports:
      - "7860:7860"
    environment:
      - LANGFLOW_HOST=0.0.0.0
      - LANGFLOW_PORT=7860
      - LANGFLOW_DATABASE_URL=sqlite:///app/langflow/langflow.db
    volumes:
      - langflow-data:/app/langflow
    networks:
      - langflow-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7860/health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  langflow-data:

networks:
  langflow-network:
    driver: bridge
EOF
    
    print_success "Created default Docker Compose file: $compose_file"
}

# Update to latest version
update_langflow() {
    local compose_file="docker-compose.yml"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compose-file)
                compose_file="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    if [ ! -f "$compose_file" ]; then
        print_error "Docker Compose file not found: $compose_file"
        exit 1
    fi

    COMPOSE_CMD=$(get_compose_cmd)
    
    print_info "Updating Langflow to latest version..."
    
    # Pull latest images
    print_info "Pulling latest images..."
    $COMPOSE_CMD -f "$compose_file" pull
    
    # Stop services
    print_info "Stopping services..."
    $COMPOSE_CMD -f "$compose_file" down
    
    # Start with new images
    print_info "Starting services with updated images..."
    $COMPOSE_CMD -f "$compose_file" up -d
    
    print_success "Update completed"
}

# Backup data
backup_data() {
    local backup_file="langflow-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    local compose_file="docker-compose.yml"
    local service="langflow"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compose-file)
                compose_file="$2"
                shift 2
                ;;
            --service)
                service="$2"
                shift 2
                ;;
            --file)
                backup_file="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    if [ ! -f "$compose_file" ]; then
        print_error "Docker Compose file not found: $compose_file"
        exit 1
    fi

    COMPOSE_CMD=$(get_compose_cmd)
    
    print_info "Creating backup: $backup_file"
    
    if $COMPOSE_CMD -f "$compose_file" ps -q "$service" | grep -q .; then
        $COMPOSE_CMD -f "$compose_file" exec "$service" tar -czf /tmp/backup.tar.gz -C /app/langflow .
        $COMPOSE_CMD -f "$compose_file" cp "$service:/tmp/backup.tar.gz" "$backup_file"
        $COMPOSE_CMD -f "$compose_file" exec "$service" rm /tmp/backup.tar.gz
        print_success "Backup created: $backup_file"
    else
        print_error "Service not running: $service"
        exit 1
    fi
}

# Restore data
restore_data() {
    local backup_file="$1"
    local compose_file="docker-compose.yml"
    local service="langflow"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compose-file)
                compose_file="$2"
                shift 2
                ;;
            --service)
                service="$2"
                shift 2
                ;;
            *)
                if [ -z "$backup_file" ]; then
                    backup_file="$1"
                fi
                shift
                ;;
        esac
    done

    if [ -z "$backup_file" ] || [ ! -f "$backup_file" ]; then
        print_error "Backup file not specified or not found"
        exit 1
    fi

    if [ ! -f "$compose_file" ]; then
        print_error "Docker Compose file not found: $compose_file"
        exit 1
    fi

    COMPOSE_CMD=$(get_compose_cmd)

    print_warning "This will replace existing data in the service"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Restoring from backup: $backup_file"
        
        if $COMPOSE_CMD -f "$compose_file" ps -q "$service" | grep -q .; then
            $COMPOSE_CMD -f "$compose_file" cp "$backup_file" "$service:/tmp/restore.tar.gz"
            $COMPOSE_CMD -f "$compose_file" exec "$service" rm -rf /app/langflow/*
            $COMPOSE_CMD -f "$compose_file" exec "$service" tar -xzf /tmp/restore.tar.gz -C /app/langflow
            $COMPOSE_CMD -f "$compose_file" exec "$service" rm /tmp/restore.tar.gz
            print_success "Data restored successfully"
        else
            print_error "Service not running: $service"
            exit 1
        fi
    else
        print_info "Restore cancelled"
    fi
}

# Clean up resources
clean_resources() {
    local compose_file="docker-compose.yml"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compose-file)
                compose_file="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    print_warning "This will remove containers, images, and volumes"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Cleaning up Docker resources..."

        if [ -f "$compose_file" ]; then
            COMPOSE_CMD=$(get_compose_cmd)
            
            # Stop and remove services, networks, and volumes defined in compose file
            $COMPOSE_CMD -f "$compose_file" down -v --rmi all 2>/dev/null || true
            
            print_success "Compose cleanup completed"
        else
            # Fallback to manual cleanup if no compose file
            print_info "No compose file found, performing manual cleanup..."
            
            # Stop and remove containers
            docker stop $(docker ps -q --filter "name=langflow") 2>/dev/null || true
            docker rm $(docker ps -aq --filter "name=langflow") 2>/dev/null || true

            # Remove images
            docker rmi $(docker images -q --filter "reference=langflowai/langflow") 2>/dev/null || true
            docker rmi $(docker images -q --filter "reference=postgres") 2>/dev/null || true
            docker rmi $(docker images -q --filter "reference=redis") 2>/dev/null || true

            # Remove volumes
            docker volume rm $(docker volume ls -q --filter "name=langflow") 2>/dev/null || true

            # Remove networks
            docker network rm $(docker network ls -q --filter "name=langflow") 2>/dev/null || true

            print_success "Manual cleanup completed"
        fi
    else
        print_info "Cleanup cancelled"
    fi
}

# Main function
main() {
    # Check if command is provided
    if [ -z "$1" ]; then
        print_error "No command specified"
        show_usage
        exit 1
    fi

    COMMAND=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    shift # Remove command from arguments

    # Check requirements
    check_requirements

    # Execute command
    case "$COMMAND" in
        run)
            run_container "$@"
            ;;
        start)
            start_container "$@"
            ;;
        stop)
            stop_container "$@"
            ;;
        restart)
            restart_container "$@"
            ;;
        logs)
            show_logs "$@"
            ;;
        status)
            show_status "$@"
            ;;
        shell)
            access_shell "$@"
            ;;
        build)
            build_image "$@"
            ;;
        deploy)
            deploy_compose "$@"
            ;;
        update)
            update_langflow "$@"
            ;;
        backup)
            backup_data "$@"
            ;;
        restore)
            restore_data "$@"
            ;;
        clean)
            clean_resources "$@"
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            print_error "Unknown command: $COMMAND"
            show_usage
            exit 1
            ;;
    esac
}

# Handle Ctrl+C gracefully
trap 'echo ""; print_info "Interrupted by user"; exit 0' INT

# Run main function
main "$@"
