#!/bin/bash

set -e
set -o pipefail

# Script: build-and-run-langflow.sh
# Purpose: Build and run Langflow using Docker Compose with .env.docker configuration
# Usage: ./build-and-run-langflow.sh [command] [options]

# Default values
COMPOSE_FILE="docker-compose.dev.yml"
ENV_FILE=".env.docker"
DEFAULT_PORT="7860"
DEFAULT_HOST="0.0.0.0"

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
    echo "Usage: ./build-and-run-langflow.sh [command]"
    echo ""
    echo "Commands:"
    echo "  up        - Start Langflow with Docker Compose"
    echo "  down      - Stop and remove Docker Compose services"
    echo "  logs      - Show Docker Compose logs"
    echo "  restart   - Restart Docker Compose services"
    echo "  status    - Show status of Docker Compose services"
    echo "  clean     - Clean up Docker resources (containers, images, volumes)"
    echo "  build     - Build Docker images without starting services"
    echo "  help      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./build-and-run-langflow.sh up"
    echo "  ./build-and-run-langflow.sh down"
    echo "  ./build-and-run-langflow.sh logs"
    echo ""
    echo "Environment:"
    echo "  Uses .env.docker for environment variables"
    echo "  Uses docker-compose.dev.yml for service configuration"
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
            print_error "Docker Compose is not installed or not in PATH"
            exit 1
        fi
    fi

    print_success "All requirements met"
    echo "$COMPOSE_CMD"
}

# Load environment variables from .env.docker
load_environment() {
    if [ ! -f "$ENV_FILE" ]; then
        print_error "Environment file $ENV_FILE not found"
        print_info "Please create $ENV_FILE with your configuration"
        exit 1
    fi

    print_info "Loading environment variables from $ENV_FILE"

    # Export environment variables
    set -o allexport
    source "$ENV_FILE"
    set +o allexport

    # Show key configuration
    print_info "Configuration:"
    echo "  Database URL: ${LANGFLOW_DATABASE_URL:-not set}"
    echo "  Host: ${LANGFLOW_HOST:-$DEFAULT_HOST}"
    echo "  Port: ${LANGFLOW_PORT:-$DEFAULT_PORT}"
    echo "  Analytics: ${LANGFLOW_ENABLE_ANALYTICS:-not set}"
}

# Get Docker Compose command
get_compose_cmd() {
    if docker compose version &> /dev/null; then
        echo "docker compose"
    else
        echo "docker-compose"
    fi
}

# Start services
start_services() {
    print_info "Starting Langflow with Docker Compose..."

    COMPOSE_CMD=$(get_compose_cmd)

    print_info "Services:"
    echo "  PostgreSQL: localhost:5432"
    echo "  Langflow: http://${LANGFLOW_HOST:-$DEFAULT_HOST}:${LANGFLOW_PORT:-$DEFAULT_PORT}"
    echo ""
    print_info "Press Ctrl+C to stop all services"

    # Start services with environment file
    $COMPOSE_CMD -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up --build
}

# Stop services
stop_services() {
    print_info "Stopping Docker Compose services..."

    COMPOSE_CMD=$(get_compose_cmd)
    $COMPOSE_CMD -f "$COMPOSE_FILE" down

    print_success "Services stopped"
}

# Show logs
show_logs() {
    print_info "Showing Docker Compose logs..."

    COMPOSE_CMD=$(get_compose_cmd)
    $COMPOSE_CMD -f "$COMPOSE_FILE" logs -f
}

# Restart services
restart_services() {
    print_info "Restarting Docker Compose services..."

    stop_services
    start_services
}

# Show status
show_status() {
    print_info "Docker Compose service status:"

    COMPOSE_CMD=$(get_compose_cmd)
    $COMPOSE_CMD -f "$COMPOSE_FILE" ps

    echo ""
    print_info "Container details:"
    docker ps --filter "name=langflow" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
}

# Clean up Docker resources
clean_docker() {
    print_warning "This will remove all Langflow-related Docker resources"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Cleaning up Docker resources..."

        # Stop and remove containers
        docker stop $(docker ps -q --filter "name=langflow") 2>/dev/null || true
        docker rm $(docker ps -aq --filter "name=langflow") 2>/dev/null || true

        # Remove images
        docker rmi $(docker images -q --filter "reference=langflow") 2>/dev/null || true

        # Remove volumes
        docker volume rm $(docker volume ls -q --filter "name=langflow") 2>/dev/null || true

        # Remove networks
        docker network rm $(docker network ls -q --filter "name=langflow") 2>/dev/null || true

        print_success "Docker cleanup completed"
    else
        print_info "Cleanup cancelled"
    fi
}

# Build images
build_images() {
    print_info "Building Docker images..."

    COMPOSE_CMD=$(get_compose_cmd)
    $COMPOSE_CMD -f "$COMPOSE_FILE" --env-file "$ENV_FILE" build

    print_success "Images built successfully"
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

    # Show version
    VERSION=$(grep "^version" pyproject.toml | sed 's/.*"\(.*\)"$$/\1/')
    print_info "Langflow version: $VERSION"

    # Check requirements
    check_requirements

    # Load environment variables
    load_environment

    # Execute command
    case "$COMMAND" in
        up|start)
            start_services
            ;;
        down|stop)
            stop_services
            ;;
        logs)
            show_logs
            ;;
        restart)
            restart_services
            ;;
        status)
            show_status
            ;;
        clean)
            clean_docker
            ;;
        build)
            build_images
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