FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY src/requirements.txt /app/src/requirements.txt
RUN pip install -r /app/src/requirements.txt

COPY src/ /app/src/
COPY abis/ /app/abis/
COPY docker/dkg-runner.sh /usr/local/bin/dkg-runner
RUN chmod +x /usr/local/bin/dkg-runner

WORKDIR /app/src
