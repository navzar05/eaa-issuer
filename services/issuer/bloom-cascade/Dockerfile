FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    libpcsclite-dev \
    pcscd \
    pcsc-tools \
    usbutils \
    libusb-1.0-0-dev \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv

COPY requirements.txt .
RUN /opt/venv/bin/pip install -r requirements.txt

# Run the application:
COPY src/cascade.py .
COPY src/CRLPublisher.py .
COPY src/main.py .
COPY src/abi.json .
COPY libeToken.so.10.8.1050 /usr/lib/libeToken.so

CMD ["/opt/venv/bin/python", "main.py"]
