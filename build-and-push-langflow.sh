#!/bin/bash

set -e
set -o pipefail

# Validate input
if [ -z "$1" ]; then
  echo "❌ Error: Environment not specified."
  echo "Usage: ./build-and-push-langflow.sh <env> [registry_url] [image_tag]"
  echo "Example: ./build-and-push-langflow.sh dev myregistry.azurecr.io latest"
  echo "Example: ./build-and-push-langflow.sh prod myregistry.azurecr.io v1.4.3"
  exit 1
fi

ENV=$(echo "$1" | tr '[:upper:]' '[:lower:]')
REGISTRY_URL="${2:-aiselstack${ENV}registry.azurecr.io}"
IMAGE_TAG="${3:-latest}"

# Map environment to configuration
case "$ENV" in
  dev)
    ENV_FILE=".env.development"
    BUILD_TYPE="development"
    ;;
  stg)
    ENV_FILE=".env.staging"
    BUILD_TYPE="staging"
    ;;
  prod)
    ENV_FILE=".env.production"
    BUILD_TYPE="production"
    ;;
  *)
    echo "❌ Unknown environment: $ENV"
    echo "Supported environments: dev, stg, prod"
    exit 1
    ;;
esac

# Check if environment file exists (optional)
if [ -f "$ENV_FILE" ]; then
  echo "📄 Loading environment variables from $ENV_FILE"
  set -o allexport
  source "$ENV_FILE"
  set +o allexport
else
  echo "⚠️  Environment file $ENV_FILE not found. Using default values."
fi

# Construct image name
IMAGE_NAME="${REGISTRY_URL}/langflow:${IMAGE_TAG}"

# Get version from pyproject.toml
VERSION=$(grep "^version" pyproject.toml | sed 's/.*"\(.*\)"$$/\1/')
echo "📦 Langflow version: $VERSION"

echo "🔧 Building Langflow Docker image for $ENV environment..."
echo "   Registry: $REGISTRY_URL"
echo "   Image: $IMAGE_NAME"
echo "   Build type: $BUILD_TYPE"

# Check if required tools are available
check_tools() {
  echo "🔍 Checking required tools..."

  if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in PATH"
    exit 1
  fi

  if ! command -v uv &> /dev/null; then
    echo "❌ uv is not installed. Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source ~/.cargo/env
  fi

  if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed"
    exit 1
  fi

  echo "✅ All required tools are available"
}

# Login to registry if it's Azure Container Registry
login_to_registry() {
  if [[ "$REGISTRY_URL" == *".azurecr.io" ]]; then
    REGISTRY_NAME=$(echo "$REGISTRY_URL" | sed 's/\.azurecr\.io//')
    echo "🔐 Logging into Azure Container Registry: $REGISTRY_NAME"

    if command -v az &> /dev/null; then
      az acr login --name "$REGISTRY_NAME" || {
        echo "⚠️  Failed to login with az cli. Please login manually:"
        echo "   docker login $REGISTRY_URL"
        read -p "Press Enter after logging in manually..."
      }
    else
      echo "⚠️  Azure CLI not found. Please login manually:"
      echo "   docker login $REGISTRY_URL"
      read -p "Press Enter after logging in manually..."
    fi
  else
    echo "🔐 Please login to your registry:"
    echo "   docker login $REGISTRY_URL"
    read -p "Press Enter after logging in..."
  fi
}

# Tag existing latest image as previous
tag_previous_image() {
  echo "🏷️  Tagging previous latest image..."

  # Check if latest image exists
  if docker pull "${REGISTRY_URL}/langflow:latest" &>/dev/null; then
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    PREVIOUS_TAG="previous-${TIMESTAMP}"

    echo "   Tagging latest as: ${PREVIOUS_TAG}"
    docker tag "${REGISTRY_URL}/langflow:latest" "${REGISTRY_URL}/langflow:${PREVIOUS_TAG}"
    docker push "${REGISTRY_URL}/langflow:${PREVIOUS_TAG}"

    echo "✅ Previous image tagged as: ${PREVIOUS_TAG}"
  else
    echo "ℹ️  No existing latest image found, skipping previous tag"
  fi
}

# Clean up old images (keep max 5)
cleanup_old_images() {
  echo "🧹 Cleaning up old images (keeping max 5)..."

  if [[ "$REGISTRY_URL" == *".azurecr.io" ]] && command -v az &> /dev/null; then
    REGISTRY_NAME=$(echo "$REGISTRY_URL" | sed 's/\.azurecr\.io//')

    # Get all tags for langflow repository
    TAGS=$(az acr repository show-tags --name "$REGISTRY_NAME" --repository langflow --orderby time_desc --output tsv 2>/dev/null || echo "")

    if [ -n "$TAGS" ]; then
      # Convert to array and keep only the first 5
      TAG_ARRAY=($TAGS)
      TOTAL_TAGS=${#TAG_ARRAY[@]}

      if [ $TOTAL_TAGS -gt 5 ]; then
        echo "   Found $TOTAL_TAGS images, keeping 5 most recent"

        # Delete older tags (skip first 5)
        for ((i=5; i<TOTAL_TAGS; i++)); do
          OLD_TAG="${TAG_ARRAY[$i]}"
          echo "   Deleting old tag: $OLD_TAG"
          az acr repository delete --name "$REGISTRY_NAME" --image "langflow:$OLD_TAG" --yes
        done

        echo "✅ Cleaned up old images"
      else
        echo "   Found $TOTAL_TAGS images (≤5), no cleanup needed"
      fi
    else
      echo "ℹ️  No existing images found"
    fi
  else
    echo "ℹ️  Skipping cleanup (not Azure or az cli not available)"
  fi
}

# Build the Docker image
build_image() {
  echo "🏗️  Building Docker image..."

  # Clean up any existing build artifacts
  echo "🧹 Cleaning build artifacts..."
  make clean_all 2>/dev/null || true

  # Build the image using the existing Dockerfile
  echo "🏗️  Starting fresh build..."
  docker buildx build \
    --platform linux/amd64 \
    -f docker/build_and_push.Dockerfile \
    -t "$IMAGE_NAME" \
    --no-cache \
    --progress=plain \
    --build-arg BUILD_TYPE="$BUILD_TYPE" \
    --build-arg NODE_ENV="$NODE_ENV" \
    .

  if [ $? -eq 0 ]; then
    echo "✅ Docker image built successfully"
  else
    echo "❌ Docker build failed"
    exit 1
  fi
}

# Push the Docker image
push_image() {
  echo "🚀 Pushing Docker image to registry..."

  docker push "$IMAGE_NAME"

  if [ $? -eq 0 ]; then
    echo "✅ Docker image pushed successfully"
  else
    echo "❌ Docker push failed"
    exit 1
  fi
}

# Update Azure Container App
update_container_app() {
  if [[ "$REGISTRY_URL" == *".azurecr.io" ]] && command -v az &> /dev/null; then
    REGISTRY_NAME=$(echo "$REGISTRY_URL" | sed 's/\.azurecr\.io//')
    APP_NAME="aisel-stack-${ENV}-langflow"
    RESOURCE_GROUP="aisel-stack-${ENV}-rg"

    echo "📦 Updating Azure Container App: $APP_NAME"

    # Check if the container app exists
    if az containerapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" &>/dev/null; then
      # Set environment variables for the container app
      ENV_VARS="LANGFLOW_DATABASE_URL=${LANGFLOW_DATABASE_URL}"
      ENV_VARS="$ENV_VARS LANGFLOW_SECRET_KEY=${LANGFLOW_SECRET_KEY}"
      ENV_VARS="$ENV_VARS LANGFLOW_AUTHENTICATION_PROXY_SECRET=${LANGFLOW_AUTHENTICATION_PROXY_SECRET}"
      ENV_VARS="$ENV_VARS AUTO_LOGIN=${AUTO_LOGIN:-false}"
      ENV_VARS="$ENV_VARS LANGFLOW_ENABLE_ANALYTICS=${LANGFLOW_ENABLE_ANALYTICS:-false}"
      ENV_VARS="$ENV_VARS DISABLE_AUTHENTICATION_PROXY=${DISABLE_AUTHENTICATION_PROXY:-false}"
      ENV_VARS="$ENV_VARS SYSTEM_MANAGERS=${SYSTEM_MANAGERS}"
      ENV_VARS="$ENV_VARS BUILD_TYPE=${BUILD_TYPE}"
      ENV_VARS="$ENV_VARS NODE_ENV=${NODE_ENV}"

      az containerapp update \
        --name "$APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --image "$IMAGE_NAME" \
        --revision-suffix "manual-$(date +%s)" \
        --set-env-vars $ENV_VARS

      echo "✅ Container app updated successfully"
    else
      echo "⚠️  Container app $APP_NAME not found in resource group $RESOURCE_GROUP"
      echo "   Skipping container app update"
    fi
  else
    echo "ℹ️  Skipping container app update (not Azure or az cli not available)"
  fi
}

# Main execution
main() {
  echo "🚀 Starting Langflow build and push process..."
  echo "   Environment: $ENV"
  echo "   Registry: $REGISTRY_URL"
  echo "   Image tag: $IMAGE_TAG"
  echo "   Version: $VERSION"
  echo ""

  check_tools
  login_to_registry
  tag_previous_image
  cleanup_old_images
  build_image
  push_image
  update_container_app

  echo ""
  echo "🎉 Deployment to $ENV complete!"
  echo "   Image: $IMAGE_NAME"
  echo "   Version: $VERSION"
  echo ""
  echo "To run the container:"
  echo "   docker run -p 7860:7860 $IMAGE_NAME"
}

# Run main function
main "$@"