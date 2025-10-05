FROM python:3.12

WORKDIR /opt/src

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TZ='Europe/Moscow'
COPY ./requirements.txt ./

# hadolint global ignore=DL3013
RUN  pip install --no-cache-dir --upgrade pip \
     && pip install --no-cache-dir -r requirements.txt

COPY ./docker/*-entrypoint.sh ./

COPY ./src/ .

RUN groupadd -r web && useradd -r -g web web && chown -R web:web /opt/src

# USER web

