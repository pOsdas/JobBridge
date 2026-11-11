FROM python:3.12-slim-trixie

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock \
    && useradd --uid 10001 --no-create-home bridge \
    && install -d -m 0700 -o bridge -g bridge /data
COPY bridge ./bridge
USER bridge
CMD ["uvicorn", "bridge.web:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--ws", "websockets", "--ws-max-size", "8388608", "--limit-concurrency", "64", "--backlog", "64", "--timeout-keep-alive", "5"]
