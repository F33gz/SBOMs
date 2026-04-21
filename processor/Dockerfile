# SBOM Processor: Python + Syft + Grype
FROM python:3.12-slim

LABEL maintainer="DevSecOps Team"
LABEL description="Clones GitHub repos, generates SBOMs with Syft, and scans vulnerabilities with Grype"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN curl -sSfL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin
RUN syft version && grype version

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
RUN mkdir -p /data

ENTRYPOINT ["python", "-u", "main.py"]
