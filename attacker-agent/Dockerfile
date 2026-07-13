FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data

ENV PORT=5002
ENV TARGET_URL=http://target-app:5000
ENV ATTACK_LOG_PATH=/app/data/attack_log.json

EXPOSE 5002

CMD ["python", "api.py"]
