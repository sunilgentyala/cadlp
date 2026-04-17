FROM python:3.11-slim

LABEL maintainer="CADLP Research Team <research@cadlp.io>"
LABEL description="Context-Aware DLP Proxy for Large Language Models"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY cadlp/ cadlp/

RUN pip install --no-cache-dir -e .

COPY tests/ tests/
COPY data/ data/

RUN useradd -m -u 1000 cadlp && chown -R cadlp:cadlp /app
USER cadlp

CMD ["cadlp", "--help"]
