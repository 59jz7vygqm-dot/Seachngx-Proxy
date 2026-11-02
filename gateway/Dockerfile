FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gw ./gw

RUN useradd -r -u 10001 gateway && chown -R gateway /app
USER gateway

EXPOSE 8000
CMD ["uvicorn", "gw.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
