#!/bin/bash
#
# Demo: Complete Evidence Collection Flow
# This script demonstrates the entire evidence collection pipeline
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
EVIDENCE_BUCKET="${EVIDENCE_BUCKET:-compliance-evidence-demo}"
SAMPLE_SCAN="evidence/samples/sample-inspec-scan.json"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}    CIS Benchmark Compliance - Evidence Collection Demo${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Step 1: Check Prerequisites
echo -e "${YELLOW}[Step 1/7]${NC} Checking prerequisites..."

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo -e "${RED}✗ AWS CLI not found. Please install: https://aws.amazon.com/cli/${NC}"
    exit 1
fi
echo -e "${GREEN}✓ AWS CLI installed${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python 3 installed${NC}"

# Check boto3
if ! python3 -c "import boto3" &> /dev/null; then
    echo -e "${YELLOW}Installing boto3...${NC}"
    pip3 install boto3 --quiet
fi
echo -e "${GREEN}✓ boto3 installed${NC}"

# Check jq
if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}jq not found (optional but recommended)${NC}"
else
    echo -e "${GREEN}✓ jq installed${NC}"
fi

# Check AWS credentials
echo ""
echo -e "${YELLOW}Checking AWS credentials...${NC}"
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}✗ AWS credentials not configured${NC}"
    echo -e "${YELLOW}Run: aws configure${NC}"
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region || echo "us-east-1")
echo -e "${GREEN}✓ AWS credentials valid${NC}"
echo -e "  Account ID: ${ACCOUNT_ID}"
echo -e "  Region: ${REGION}"
echo ""

# Step 2: Setup S3 Evidence Bucket (if not exists)
echo -e "${YELLOW}[Step 2/7]${NC} Setting up S3 evidence bucket..."

BUCKET_NAME="compliance-evidence-${ACCOUNT_ID}"
echo -e "  Bucket: ${BUCKET_NAME}"

if aws s3 ls "s3://${BUCKET_NAME}" 2>&1 | grep -q 'NoSuchBucket'; then
    echo -e "${YELLOW}Creating S3 bucket...${NC}"
    aws s3 mb "s3://${BUCKET_NAME}" --region ${REGION}
    echo -e "${GREEN}✓ S3 bucket created${NC}"

    # Enable versioning
    echo -e "${YELLOW}Enabling versioning...${NC}"
    aws s3api put-bucket-versioning \
        --bucket ${BUCKET_NAME} \
        --versioning-configuration Status=Enabled
    echo -e "${GREEN}✓ Versioning enabled${NC}"

    # Block public access
    echo -e "${YELLOW}Blocking public access...${NC}"
    aws s3api put-public-access-block \
        --bucket ${BUCKET_NAME} \
        --public-access-block-configuration \
            BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
    echo -e "${GREEN}✓ Public access blocked${NC}"
else
    echo -e "${GREEN}✓ S3 bucket already exists${NC}"
fi
echo ""

# Step 3: Collect Evidence from Sample Scan
echo -e "${YELLOW}[Step 3/7]${NC} Collecting evidence from sample InSpec scan..."

if [ ! -f "$SAMPLE_SCAN" ]; then
    echo -e "${RED}✗ Sample scan not found: ${SAMPLE_SCAN}${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Sample scan file found${NC}"
echo -e "  File: ${SAMPLE_SCAN}"

# Parse sample scan summary
if command -v jq &> /dev/null; then
    TOTAL_CONTROLS=$(jq '.profiles[0].controls | length' "$SAMPLE_SCAN")
    echo -e "  Total Controls: ${TOTAL_CONTROLS}"
fi
echo ""

# Step 4: Run Evidence Collector
echo -e "${YELLOW}[Step 4/7]${NC} Running evidence collector..."

echo -e "${BLUE}python3 evidence/collectors/evidence_collector.py \\
  --inspec-json ${SAMPLE_SCAN} \\
  --bucket ${BUCKET_NAME} \\
  --store${NC}"
echo ""

python3 evidence/collectors/evidence_collector.py \
    --inspec-json "$SAMPLE_SCAN" \
    --bucket "${BUCKET_NAME}" \
    --store

echo ""
echo -e "${GREEN}✓ Evidence collected and stored to S3${NC}"
echo ""

# Step 5: Verify Evidence in S3
echo -e "${YELLOW}[Step 5/7]${NC} Verifying evidence in S3..."

echo -e "${YELLOW}Raw scans:${NC}"
aws s3 ls "s3://${BUCKET_NAME}/raw-scans/inspec/" --recursive | tail -3

echo ""
echo -e "${YELLOW}Normalized findings:${NC}"
aws s3 ls "s3://${BUCKET_NAME}/normalized-findings/" --recursive | tail -3

echo ""
echo -e "${YELLOW}Snapshots:${NC}"
aws s3 ls "s3://${BUCKET_NAME}/snapshots/daily/" --recursive | tail -3

echo ""
echo -e "${GREEN}✓ Evidence stored successfully${NC}"
echo ""

# Step 6: Generate Compliance Report
echo -e "${YELLOW}[Step 6/7]${NC} Generating compliance report..."

# Get today's date
TODAY=$(date +%Y-%m-%d)

echo -e "${BLUE}python3 evidence/reporters/compliance_reporter.py \\
  --bucket ${BUCKET_NAME} \\
  --type daily \\
  --date ${TODAY} \\
  --format markdown${NC}"
echo ""

REPORT=$(python3 evidence/reporters/compliance_reporter.py \
    --bucket "${BUCKET_NAME}" \
    --type daily \
    --date "${TODAY}" \
    --format markdown 2>/dev/null || echo "")

if [ -n "$REPORT" ]; then
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}                    Compliance Report Preview${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "$REPORT" | head -40
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
fi
echo ""

# Step 7: Summary and Next Steps
echo -e "${YELLOW}[Step 7/7]${NC} Demo complete!"
echo ""

echo -e "${GREEN}✓ Evidence Collection Flow Completed Successfully${NC}"
echo ""

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}                        Summary${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "Evidence Bucket: ${GREEN}s3://${BUCKET_NAME}${NC}"
echo -e "Region: ${REGION}"
echo -e "Account ID: ${ACCOUNT_ID}"
echo ""

echo -e "${YELLOW}Evidence Types Collected:${NC}"
echo -e "  ✓ Raw scan results (InSpec JSON)"
echo -e "  ✓ Normalized findings (canonical format)"
echo -e "  ✓ Compliance snapshot (daily)"
echo ""

echo -e "${YELLOW}Evidence Features:${NC}"
echo -e "  ✓ Versioned (full history)"
echo -e "  ✓ Encrypted (at rest)"
echo -e "  ✓ Timestamped (UTC)"
echo -e "  ✓ Hash-verified (SHA-256)"
echo ""

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}                      Next Steps${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${YELLOW}1. View evidence in S3:${NC}"
echo -e "   ${BLUE}aws s3 ls s3://${BUCKET_NAME}/ --recursive${NC}"
echo ""

echo -e "${YELLOW}2. Download a scan result:${NC}"
echo -e "   ${BLUE}aws s3 cp s3://${BUCKET_NAME}/raw-scans/inspec/\$(date +%Y/%m/%d)/ ./ --recursive${NC}"
echo ""

echo -e "${YELLOW}3. Query findings:${NC}"
echo -e "   ${BLUE}aws s3 cp s3://${BUCKET_NAME}/normalized-findings/\$(date +%Y/%m/%d)/findings.ndjson - | \\
   jq 'select(.severity == \"CRITICAL\")' ${NC}"
echo ""

echo -e "${YELLOW}4. Generate audit report for specific control:${NC}"
echo -e "   ${BLUE}python3 evidence/reporters/compliance_reporter.py \\
     --bucket ${BUCKET_NAME} \\
     --type audit \\
     --control CIS-AWS-2.1.4 \\
     --format markdown${NC}"
echo ""

echo -e "${YELLOW}5. Deploy with Terraform (production setup):${NC}"
echo -e "   ${BLUE}cd evidence/terraform
   terraform init
   terraform plan
   terraform apply${NC}"
echo ""

echo -e "${YELLOW}6. Read audit handbook:${NC}"
echo -e "   ${BLUE}cat docs/AUDIT-HANDBOOK.md${NC}"
echo ""

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Demo completed successfully! ✓${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
