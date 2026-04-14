FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    tcpdump \
    iputils-ping \
    arping \
    net-tools \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash appuser

WORKDIR /app

COPY . /app/

RUN pip install --no-cache-dir .

RUN mkdir -p /var/log/tc /var/run/tc && chown -R appuser:appuser /app

USER appuser

CMD ["evillimiter", "-h"]
