# 베이스 이미지로 Python 3.9-slim을 사용합니다.
FROM python:3.9-slim

# 작업 디렉터리를 /app으로 설정합니다.
WORKDIR /app

# 시스템 패키지를 업데이트하고, 바이너리 분석에 필요한 도구들을 설치합니다.
# build-essential: C 코드를 컴파일하는 데 필요 (checksec 설치 시 사용될 수 있음)
# git: checksec과 같은 도구를 소스에서 클론할 때 필요할 수 있음
# procps: psutil과 같은 라이브러리가 시스템 정보를 읽는 데 사용
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    procps \
    && rm -rf /var/lib/apt/lists/*

# checksec 도구를 설치합니다.
# checksec은 ELF 바이너리 보안 속성을 확인하는 데 사용됩니다.
RUN git clone https://github.com/slimm609/checksec.sh.git /opt/checksec.sh \
    && ln -s /opt/checksec.sh/checksec /usr/local/bin/checksec

# requirements.txt 파일을 컨테이너에 복사합니다.
COPY requirements.txt .

# pip를 최신 버전으로 업그레이드하고 requirements.txt에 명시된 라이브러리를 설치합니다.
RUN pip install --no-cache-dir -r requirements.txt

# 현재 디렉터리의 모든 파일을 컨테이너의 /app 디렉터리로 복사합니다.
COPY . .

# 컨테이너가 시작될 때 실행할 기본 명령어를 설정합니다.
# python3으로 main.py를 실행합니다.
ENTRYPOINT ["python3", "main.py"]