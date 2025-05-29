FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies for both Java and Python
RUN apt-get update && apt-get install -y \
    libpcsclite1 pcsc-tools opensc psmisc default-jre supervisor \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
 

COPY ./libeToken.so.10.8.1050 /usr/lib/libeToken.so
COPY ./libeToken.so.10.8.1050 /usr/lib/libeTPkcs11.so

WORKDIR /app
# ARG CACHEBUST

COPY target/spring-issuer-0.0.1-SNAPSHOT.jar /app/app.jar
COPY cascade_cli /app/cascade_cli
COPY state_list.txt /app/revocation-list.txt
# COPY last_ipfs_hash.txt /app/last_ipfs_hash.txt

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
#
EXPOSE 8081

CMD ["/usr/bin/supervisord"]