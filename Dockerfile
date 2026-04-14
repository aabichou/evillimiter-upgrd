FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    tcpdump \
    iputils-ping \
    arping \
    net-tools \
    libpcap-dev \
    gcc \
    python3-dev \
    sudo \
    procps \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash appuser

WORKDIR /app

COPY . /app/

RUN pip install --no-cache-dir .

RUN mkdir -p /var/log/tc /var/run/tc

ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Keep root for iptables/tc access
CMD ["evillimiter", "-h"]
