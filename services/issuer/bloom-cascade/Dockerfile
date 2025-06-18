FROM python:3.12-slim

RUN python3 -m venv /opt/venv

COPY requirements.txt .
RUN /opt/venv/bin/pip install -r requirements.txt

# Run the application:
COPY src/cascade.py .
COPY src/CRLPublisher.py .
COPY src/main.py .
COPY src/abi.json .

CMD ["/opt/venv/bin/python", "main.py"]
