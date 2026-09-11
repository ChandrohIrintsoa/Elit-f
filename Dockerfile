FROM python:3.13-slim

RUN groupadd -g 999 appuser && \
    useradd -r -u 999 -g appuser appuser

WORKDIR /app

COPY . .

RUN apt-get -qq update && apt-get -qq install -y \
    git \
    cmake \
    build-essential \
    ninja-build \
    pkg-config \
    libicu-dev \
    libcapstone-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv --copies /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir pyelftools requests rich

RUN chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["python", "elitf.py"]
