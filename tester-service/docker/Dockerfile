FROM python:3.12

WORKDIR /opt/src

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TZ='Europe/Moscow'
COPY ./requirements.txt ./
RUN apt-get update && apt-get install -y tcpdump && apt-get install -y openssh-server
RUN echo 'root:rootpassword' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
EXPOSE 22
# hadolint global ignore=DL3013
RUN  pip install --no-cache-dir --upgrade pip \
     && pip install --no-cache-dir -r requirements.txt

COPY ./docker/*-entrypoint.sh ./

COPY ./src/ .

RUN groupadd -r web && useradd -r -g web web && chown -R web:web /opt/src

# USER web

