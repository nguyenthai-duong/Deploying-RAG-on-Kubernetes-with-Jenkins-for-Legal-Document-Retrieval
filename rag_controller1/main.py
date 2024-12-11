from fastapi import FastAPI, HTTPException
import weaviate
import requests
from pyvi.ViTokenizer import tokenize
from llama_index.core import PromptTemplate
import os
import logging
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import get_tracer_provider, set_tracer_provider
from opentelemetry import trace  
import uvicorn
import asyncio  

JAEGER_HOST = os.getenv("JAEGER_HOST", "jaeger-tracing-jaeger-all-in-one.jaeger-tracing.svc.cluster.local")
JAEGER_PORT = os.getenv("JAEGER_PORT", "6831")

WEAVIATE_URL = os.getenv("WEAVIATE_URL", "http://weaviate.weaviate.svc.cluster.local:85")
VECTORIZE_URL = os.getenv("VECTORIZE_URL", "http://emb-svc.emb.svc.cluster.local:81/vectorize")
LLM_API_URL = os.getenv("LLM_API_URL", "https://nthaiduong83.serveo.net/generate")

MAX_NEW_TOKENS = int(os.getenv("MAX_NEW_TOKENS", 30))
TEMPERATURE = float(os.getenv("TEMPERATURE", 0.5))

trace_provider = TracerProvider(resource=Resource.create({SERVICE_NAME: "RAG-Query-from-user"}))
set_tracer_provider(trace_provider)
tracer = get_tracer_provider().get_tracer("myllm", "0.1.2")

jaeger_exporter = JaegerExporter(
    agent_host_name=JAEGER_HOST,
    agent_port=int(JAEGER_PORT),
)
span_processor = BatchSpanProcessor(jaeger_exporter)
trace_provider.add_span_processor(span_processor)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING) 

app = FastAPI(
    title="Rag",
    docs_url="/rag/docs",
    redoc_url="/rag/redoc",
    openapi_url="/rag/openapi.json")

@app.get("/healthz")
async def health_check():
    return {"status": "ok"}

async def query_rag_llm(query_str, limit=3):
    with tracer.start_as_current_span("processors") as processors_span:

        with tracer.start_as_current_span(
            "Tokenize Query", links=[trace.Link(processors_span.get_span_context())]
        ):
            logger.warning("Đã nhận query và đang chuẩn bị tokenizing")
            tokenized_query = tokenize(query_str)
            logger.warning(f"Tokenizing done: {tokenized_query}")

        with tracer.start_as_current_span(
            "Weaviate Search", links=[trace.Link(processors_span.get_span_context())]
        ):
            logger.warning("Connecting to Weaviate and finding top K")
            client = weaviate.Client(WEAVIATE_URL)

            text_data = {"text": tokenized_query}
            response = await asyncio.to_thread(requests.post, VECTORIZE_URL, json=text_data)

            if response.status_code == 200:
                vec = response.json().get("vector")
            else:
                print("Failed to get vector, status code:", response.status_code)
                return None

            near_vec = {"vector": vec}

            res = await asyncio.to_thread(client.query.get("Document", ["content", "_additional {certainty}"]).with_near_vector(near_vec).with_limit(limit).do)

            context_str = []
            for document in res["data"]["Get"]["Document"]:
                logger.warning(f"Content similarity: {document['_additional']['certainty']}: {document['content']}")
                context_str.append("{:.4f}: {}".format(document["_additional"]["certainty"], document["content"]))

            context_str = "\n".join(context_str)
            

        with tracer.start_as_current_span(
            "Create Prompt and Call LLM", links=[trace.Link(processors_span.get_span_context())]
        ):
            logger.warning("Creating template and going into LLM")
            template = (
                "We have provided context information below. \n"
                "---------------------\n"
                "{context_str}"
                "\n---------------------\n"
                "Given this information, please answer the question: {query_str}\n"
            )
            qa_template = PromptTemplate(template)
            messages = qa_template.format_messages(context_str=context_str, query_str=query_str)
            prompt = messages[0].content

            response = await asyncio.to_thread(requests.post, 
                LLM_API_URL,
                json={
                    "inputs": prompt,
                    "parameters": {
                        "max_new_tokens": MAX_NEW_TOKENS,
                        "temperature": TEMPERATURE
                    }
                },
                verify=False  # Disable SSL certificate verification
            )

            if response.status_code == 200:
                response_json = response.json()
                logger.warning(f"Answer from LLM: {response_json}")
                return response_json
            else:
                print("Failed to get response from LLM, status code:", response.status_code)
                logger.warning(f"Error: {response_json}")
                return None

@app.post("/query")
async def query(query_str: str):
    response = await query_rag_llm(query_str)
    if response:
        return {"response": response}
    else:
        raise HTTPException(status_code=500, detail="Failed to process the query")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8005, reload=True)
