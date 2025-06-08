FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies for both Java and Python
RUN apt-get update && apt-get install -y \
    libpcsclite1 pcsc-tools opensc psmisc default-jre \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy token libraries
COPY ./libeToken.so.10.8.1050 /usr/lib/libeToken.so
COPY ./libeToken.so.10.8.1050 /usr/lib/libeTPkcs11.so

WORKDIR /app

# Copy application files
COPY target/spring-issuer-0.0.1-SNAPSHOT.jar /app/app.jar
COPY cascade_cli /app/cascade_cli
COPY state_list.txt /app/revocation-list.txt

EXPOSE 8081

# Run the Spring Boot application directly
CMD ["java", "-jar", "-Dspring.profiles.active=docker", "/app/app.jar"]
