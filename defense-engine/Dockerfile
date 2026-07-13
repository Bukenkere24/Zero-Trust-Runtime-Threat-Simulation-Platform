FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engine.py .

RUN mkdir -p /app/data

ENV DATA_DIR=/app/data
ENV PORT=5001

EXPOSE 5001

CMD ["python", "engine.py"]
