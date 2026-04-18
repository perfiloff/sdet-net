FROM frrouting/frr:v8.4.1

USER root

RUN apk add --no-cache openssh \
    && ssh-keygen -A

RUN echo 'root:rootpassword' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

COPY dut-service/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
