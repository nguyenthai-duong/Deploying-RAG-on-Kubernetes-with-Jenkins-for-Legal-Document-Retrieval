from fastapi import FastAPI, HTTPException, File, UploadFile
import weaviate
import requests
import os
import json
from pyvi.ViTokenizer import tokenize
import logging
import numpy as np

WEAVIATE_URL = os.getenv("WEAVIATE_URL", "http://weaviate.weaviate.svc.cluster.local:85")
VECTORIZE_URL = os.getenv("VECTORIZE_URL", "http://emb-svc.emb.svc.cluster.local:81/vectorize")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING) 

app = FastAPI(    
    title="Indexing",
    docs_url="/idx/docs",  
    redoc_url="/idx/redoc",
    openapi_url="/idx/openapi.json")

client = weaviate.Client(WEAVIATE_URL, startup_period=40)


@app.get("/healthz")
async def health_check():
    return {"status": "ok"}

@app.get("/readyz")
async def readiness_check():
    try:
        client.schema.get()  
        requests.get(VECTORIZE_URL)  
        return {"status": "ready"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Service not ready")


def init_weaviate_schema(client):
    schema = {
        "classes": [{
            "class": "Document",
            "vectorizer": "none",  
            "properties": [{
                "name": "content",
                "dataType": ["text"],
            }]
        }]
    }

    client.schema.delete_all()

    client.schema.create(schema)

def vectorize_documents(document):
    logger.warning("Gửi yêu cầu vectorize đến API")
    response = requests.post(VECTORIZE_URL, json={"text": document})  
    if response.status_code == 200:
        logger.warning("Vectorize thành công")
        return response.json().get("vector")
    else:
        logger.error(f"Vectorize thất bại với mã lỗi {response.status_code}")
        raise HTTPException(status_code=response.status_code, detail="Failed to vectorize document")

def import_documents_with_vectors(documents, vectors, client):
    if len(documents) != len(vectors):
        raise Exception("Số lượng documents ({}) và vectors ({}) không khớp".format(len(documents), len(vectors)))
        
    for i, document in enumerate(documents):
        try:
            client.data_object.create(
                data_object={"content": document},
                class_name='Document',
                vector=vectors[i]
            )
        except Exception as e:
            print(f"Error importing document {i}: {e}")

@app.post("/embed_and_import_json")
async def embed_and_import_json(file: UploadFile = File(...)):
    try:
        logger.warning("Đang đọc file JSON")
        json_data = json.load(file.file)
    except json.JSONDecodeError:
        logger.error("Lỗi: File không phải là JSON hợp lệ")
        raise HTTPException(status_code=400, detail="Invalid JSON file")

    logger.warning("Đang chuyển đổi dữ liệu JSON thành chuỗi text")
    processed_documents = []
    for item in json_data:
        combined_text = f"Trích dẫn ở: {item['title']} \n Nội dung như sau: {item['context']}"
        processed_documents.append(combined_text)
    
    logger.warning("Đang tokenize các chuỗi text")
    tokenizer_sent = [tokenize(sent) for sent in processed_documents]

    logger.warning("Đang khởi tạo schema cho Weaviate")
    init_weaviate_schema(client)

    vectors = []
    for idx, tokenized_text in enumerate(tokenizer_sent):
        logger.warning(f"Đang vectorize document {idx + 1}/{len(tokenizer_sent)}")
        vector = vectorize_documents(tokenized_text)
        vectors.append(vector)
    vectors = np.array(vectors)
    
    logger.warning("Đang import các documents và vectors vào Weaviate")
    import_documents_with_vectors(processed_documents, vectors, client)

    logger.warning("Tất cả các documents đã được import thành công vào Weaviate")
    return {"message": "All documents successfully imported into Weaviate"}

if __name__ == "__main__":
    init_weaviate_schema(client)
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8005, reload=True)
