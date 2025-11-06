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
echo -e "${GREEN}║      파일 암호화 시스템 v1.0 (auto)     ║${NC}"
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
        echo -e "암호화 중 일부 오류가 발생했을 수 있습니다.${NC}"
fi

# 정리 자동 수행
echo -e "${BLUE}임시 파일 정리 중...${NC}"
rm -f encrypt encrypt.c

echo -e "${GREEN}✓ 정리 완료${NC}"
echo ""
echo -e "${GREEN}프로그램을 종료합니다.${NC}"
