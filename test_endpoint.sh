#!/bin/bash

# Test script for CSE KACLS endpoint
# Usage: ./test_endpoint.sh [SERVICE_URL]

SERVICE_URL=${1:-"http://localhost:8080"}

echo "Testing CSE KACLS endpoint at: $SERVICE_URL"
echo ""

# Test 1: Health check
echo "=== Test 1: Health Check ==="
curl -s "$SERVICE_URL/health" | jq '.'
echo ""
echo ""

# Test 2: Wrap operation (requires authentication token)
echo "=== Test 2: Wrap Operation ==="
echo "Note: This will fail without a valid Bearer token"
echo "Testing with sample data..."
curl -s -X POST "$SERVICE_URL/v1/wrap" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-token" \
  -d '{
    "key": "SGVsbG8gV29ybGQh",
    "authorization": {
      "resource_name": "test-resource",
      "user_email": "test@example.com"
    }
  }' | jq '.'
echo ""
echo ""

# Test 3: Unwrap operation
echo "=== Test 3: Unwrap Operation ==="
echo "Note: This will fail without a valid Bearer token"
curl -s -X POST "$SERVICE_URL/v1/unwrap" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-token" \
  -d '{
    "wrappedKey": "encrypted-key-placeholder",
    "authorization": {
      "resource_name": "test-resource",
      "user_email": "test@example.com"
    }
  }' | jq '.'
echo ""
echo ""

echo "=== Testing Complete ==="
echo ""
echo "Notes:"
echo "- Health check should return {\"status\":\"healthy\"}"
echo "- Wrap/Unwrap operations require valid Google OAuth2 tokens"
echo "- These endpoints will be called by Google Workspace, not directly by users"
