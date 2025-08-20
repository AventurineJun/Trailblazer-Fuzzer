#!/bin/bash

# 스크립트 실행 중 오류가 발생하면 즉시 중단합니다.
set -e

# 이미지 이름을 설정합니다.
IMAGE_NAME="trailblazer-fuzzer"

echo ">>> Docker 이미지를 빌드합니다: $IMAGE_NAME"

# Dockerfile을 사용하여 이미지를 빌드합니다.
# --no-cache 옵션을 사용하면 항상 최신 상태로 빌드합니다. (필요 시 주석 처리)
docker build -t $IMAGE_NAME .

echo ""
echo ">>> 빌드가 완료되었습니다."
echo ">>> 컨테이너를 실행합니다. (Ctrl+C로 종료)"
echo ""

# Docker 컨테이너를 실행합니다.
# -it: 상호작용 가능한 터미널을 사용합니다.
# --rm: 컨테이너 종료 시 자동으로 삭제합니다.
# --cap-add=SYS_PTRACE: psutil과 같은 도구가 프로세스 정보를 더 잘 읽을 수 있도록 권한을 추가합니다.
docker run -it --rm --cap-add=SYS_PTRACE --name ${IMAGE_NAME}-run ${IMAGE_NAME}
