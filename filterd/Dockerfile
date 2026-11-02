FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ARG SPACY_DE=de_core_news_md
ARG SPACY_EN=en_core_web_md

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && python -m spacy download ${SPACY_DE} \
 && python -m spacy download ${SPACY_EN}

COPY pii ./pii

RUN useradd -r -u 10002 filterd && mkdir -p /app/config && chown -R filterd /app
USER filterd

EXPOSE 8001
CMD ["uvicorn", "pii.main:app", "--host", "0.0.0.0", "--port", "8001", "--no-access-log"]
