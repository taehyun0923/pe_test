#!/bin/bash

# 컬러 설정
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

cd "$(dirname "$0")"
clear

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      파일 복구 시스템 v1.0 (auto)     ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""

# 1단계: 필요한 도구 확인 및 설치
echo -e "${BLUE}[1/4] 필요한 도구 확인 중...${NC}"
NEED_INSTALL=false

if ! command -v steghide &>/dev/null; then
    echo "  - steghide 필요"
    NEED_INSTALL=true
fi
if ! command -v gcc &>/dev/null; then
    echo "  - gcc 필요"
    NEED_INSTALL=true
fi
if ! ldconfig -p 2>/dev/null | grep -q libssl; then
    echo "  - libssl 필요"
    NEED_INSTALL=true
fi

if [ "$NEED_INSTALL" = true ]; then
    echo ""
    echo -e "${YELLOW}필요한 도구를 설치합니다...${NC}"
    sudo apt-get update -qq
    sudo apt-get install -y steghide build-essential libssl-dev
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ 설치 실패${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ 도구 준비 완료${NC}"
echo ""

# 2단계: 이미지에서 decrypt.c 추출
echo -e "${BLUE}[2/4] 이미지에서 복호화 프로그램 추출 중...${NC}"

IMAGE_FILE=""
for ext in jpg jpeg png JPG JPEG PNG; do
    for file in *.$ext; do
        if [ -f "$file" ]; then
            IMAGE_FILE="$file"
            break 2
        fi
    done
done

if [ -z "$IMAGE_FILE" ]; then
    echo -e "${RED}✗ 이미지 파일을 찾을 수 없습니다!${NC}"
    exit 1
fi

echo "  이미지 파일: $IMAGE_FILE"

steghide extract -sf "$IMAGE_FILE" -p "" -xf decrypt.c 2>/dev/null
if [ ! -f decrypt.c ]; then
    echo -e "${RED}✗ decrypt.c 추출 실패${NC}"
    exit 1
fi

echo -e "${GREEN}✓ 프로그램 추출 완료${NC}"
echo ""

# 3단계: 컴파일
echo -e "${BLUE}[3/4] 복호화 프로그램 컴파일 중...${NC}"
gcc -o decrypt decrypt.c -lssl -lcrypto 2>/dev/null
if [ $? -ne 0 ] || [ ! -f decrypt ]; then
    echo -e "${RED}✗ 컴파일 실패${NC}"
    exit 1
fi
chmod +x decrypt
echo -e "${GREEN}✓ 컴파일 완료${NC}"
echo ""

# 4단계: 복호화 자동 실행
echo -e "${BLUE}[4/4] 파일 복호화 시작...${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${RED}주의: /home/ 디렉토리의 모든 .enc 파일이 복호화됩니다!${NC}"
echo ""
echo -e "${YELLOW}자동으로 계속 진행합니다...${NC}"
echo ""

sudo ./decrypt
EXIT_CODE=$?

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ 모든 작업이 완료되었습니다!${NC}"
else
    echo -e "${RED}⚠ 복호화 중 일부 오류가 발생했을 수 있습니다.${NC}"
fi

# 정리 자동 수행
echo -e "${BLUE}임시 파일 정리 중...${NC}"
rm -f decrypt decrypt.c
echo -e "${GREEN}✓ 정리 완료${NC}"

echo ""
echo -e "${GREEN}프로그램을 종료합니다.${NC}"
