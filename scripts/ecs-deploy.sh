#!/usr/bin/env bash
set -euo pipefail

# Argus ECS Fargate Deployment Script
# Usage: ./scripts/ecs-deploy.sh [--tag TAG] [--region REGION]
#
# Prerequisites:
#   - AWS CLI configured (aws sts get-caller-identity)
#   - Docker with buildx support
#   - ECR repository 'argus' already created
#   - ECS cluster 'argus' and service 'argus-sentinel' already exist
#
# Environment variables (optional overrides):
#   AWS_ACCOUNT_ID    — auto-detected if not set
#   AWS_REGION        — default: ap-northeast-2
#   ECR_REPO          — default: argus
#   ECS_CLUSTER       — default: argus
#   ECS_SERVICE       — default: argus-sentinel
#   TASK_FAMILY       — default: argus-sentinel

# --- Defaults ---
TAG="latest"
REGION="${AWS_REGION:-ap-northeast-2}"
ECR_REPO="${ECR_REPO:-argus}"
ECS_CLUSTER="${ECS_CLUSTER:-argus}"
ECS_SERVICE="${ECS_SERVICE:-argus-sentinel}"
TASK_FAMILY="${TASK_FAMILY:-argus-sentinel}"

# --- Parse args ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)
            TAG="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--tag TAG] [--region REGION]"
            echo ""
            echo "Builds the Argus Docker image, pushes to ECR, and updates the ECS Fargate service."
            echo ""
            echo "Options:"
            echo "  --tag TAG        Image tag (default: latest)"
            echo "  --region REGION  AWS region (default: ap-northeast-2)"
            echo ""
            echo "Environment variables:"
            echo "  AWS_ACCOUNT_ID, ECR_REPO, ECS_CLUSTER, ECS_SERVICE, TASK_FAMILY"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# --- Detect AWS Account ID ---
ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
ECR_URI="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}"

echo "=== Argus ECS Deploy ==="
echo "  Account:  ${ACCOUNT_ID}"
echo "  Region:   ${REGION}"
echo "  ECR:      ${ECR_URI}:${TAG}"
echo "  Cluster:  ${ECS_CLUSTER}"
echo "  Service:  ${ECS_SERVICE}"
echo ""

# --- Step 1: Build ---
echo "[1/5] Building Docker image (linux/amd64)..."
docker buildx build --platform linux/amd64 -t "argus:${TAG}" .

# --- Step 2: ECR Login ---
echo "[2/5] Logging in to ECR..."
aws ecr get-login-password --region "${REGION}" | \
    docker login --username AWS --password-stdin \
    "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

# --- Step 3: Tag & Push ---
echo "[3/5] Pushing ${ECR_URI}:${TAG}..."
docker tag "argus:${TAG}" "${ECR_URI}:${TAG}"
docker push "${ECR_URI}:${TAG}"

# --- Step 4: Update ECS Service ---
echo "[4/5] Updating ECS service (force new deployment)..."
CURRENT_TASK_DEF=$(aws ecs describe-services \
    --cluster "${ECS_CLUSTER}" \
    --services "${ECS_SERVICE}" \
    --region "${REGION}" \
    --query 'services[0].taskDefinition' \
    --output text)

# Get current task def, update image, register new revision
TASK_DEF_JSON=$(aws ecs describe-task-definition \
    --task-definition "${CURRENT_TASK_DEF}" \
    --region "${REGION}" \
    --query 'taskDefinition.{containerDefinitions:containerDefinitions,family:family,networkMode:networkMode,requiresCompatibilities:requiresCompatibilities,cpu:cpu,memory:memory,executionRoleArn:executionRoleArn}')

# Replace old image with new tag
UPDATED_JSON=$(echo "${TASK_DEF_JSON}" | \
    sed "s|${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:[^\"]*|${ECR_URI}:${TAG}|g")

NEW_REVISION=$(aws ecs register-task-definition \
    --cli-input-json "${UPDATED_JSON}" \
    --region "${REGION}" \
    --query 'taskDefinition.revision' \
    --output text)

aws ecs update-service \
    --cluster "${ECS_CLUSTER}" \
    --service "${ECS_SERVICE}" \
    --task-definition "${TASK_FAMILY}:${NEW_REVISION}" \
    --force-new-deployment \
    --region "${REGION}" \
    --query 'service.deployments[0].status' \
    --output text

# --- Step 5: Verify ---
echo "[5/5] Waiting for deployment to stabilize..."
aws ecs wait services-stable \
    --cluster "${ECS_CLUSTER}" \
    --services "${ECS_SERVICE}" \
    --region "${REGION}" 2>/dev/null || true

# Get task IP for health check
TASK_ARN=$(aws ecs list-tasks \
    --cluster "${ECS_CLUSTER}" \
    --service-name "${ECS_SERVICE}" \
    --query 'taskArns[0]' \
    --output text \
    --region "${REGION}")

if [[ "${TASK_ARN}" != "None" && -n "${TASK_ARN}" ]]; then
    TASK_IP=$(aws ecs describe-tasks \
        --cluster "${ECS_CLUSTER}" \
        --tasks "${TASK_ARN}" \
        --query 'tasks[0].attachments[0].details[?name==`privateIPv4Address`].value' \
        --output text \
        --region "${REGION}" 2>/dev/null || echo "unknown")

    echo ""
    echo "=== Deploy Complete ==="
    echo "  Task:     ${TASK_FAMILY}:${NEW_REVISION}"
    echo "  Task ARN: ${TASK_ARN}"
    echo "  Task IP:  ${TASK_IP}"
    echo ""
    echo "  Health:   curl http://${TASK_IP}:9090/health"
    echo "  Metrics:  curl http://${TASK_IP}:9090/metrics"
else
    echo ""
    echo "=== Deploy Complete ==="
    echo "  Task:     ${TASK_FAMILY}:${NEW_REVISION}"
    echo "  Note:     Task not yet running. Check ECS console."
fi
