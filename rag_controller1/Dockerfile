# Use an official Python runtime as a parent image
FROM python:3.9-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8005

ENV WEAVIATE_URL=http://weaviate.weaviate.svc.cluster.local:85
ENV VECTORIZE_URL=http://emb-svc.emb.svc.cluster.local:81/vectorize
ENV LLM_API_URL=https://nthaiduong83.serveo.net/complete
ENV MAX_NEW_TOKENS=30
ENV TEMPERATURE=0.5
ENV JAEGER_HOST=http://jaeger-tracing-jaeger-all-in-one.jaeger-tracing.svc.cluster.local
ENV JAEGER_PORT=6831

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8005"]
