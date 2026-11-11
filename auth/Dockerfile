FROM python:3.12-slim-trixie

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock \
    && useradd --uid 10003 --no-create-home auth \
    && install -d -m 0700 -o auth -g auth /auth
COPY hh_auth.py ./
USER auth
CMD ["python", "-m", "hh_auth", "run"]
