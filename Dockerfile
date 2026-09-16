FROM python:3.13-slim

ARG APP_UID=1000
ARG APP_GID=1000
RUN groupadd -g ${APP_GID} appuser && \
    useradd -m -u ${APP_UID} -g appuser appuser

WORKDIR /app

COPY . .

RUN apt-get -qq update && apt-get -qq install -y \
    git \
    cmake \
    build-essential \
    ninja-build \
    pkg-config \
    libicu-dev \
    libfmt-dev \
    libcapstone-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv --copies /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir pyelftools requests rich

RUN chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["python", "elitf.py"]
