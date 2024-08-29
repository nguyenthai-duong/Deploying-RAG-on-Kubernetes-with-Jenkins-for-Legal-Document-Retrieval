FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

ENV WEAVIATE_URL=http://weaviate.weaviate.svc.cluster.local:85
ENV VECTORIZE_URL=http://emb-svc.emb.svc.cluster.local:81/vectorize

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8005", "--reload"]
