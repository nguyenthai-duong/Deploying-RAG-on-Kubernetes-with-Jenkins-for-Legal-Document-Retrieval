from fastapi import FastAPI, Request
from pydantic import BaseModel
import torch
from transformers import AutoModel, AutoTokenizer
import uvicorn

app = FastAPI()

model_name = "dangvantuan/vietnamese-embedding"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModel.from_pretrained(model_name)

class TextRequest(BaseModel):
    text: str

def text2vec(text):
    tokens_pt = tokenizer(text, padding=True, truncation=True, max_length=500, add_special_tokens=True, return_tensors="pt")
    outputs = model(**tokens_pt)
    return outputs[0].mean(0).mean(0).detach().cpu().numpy().tolist()

@app.post("/vectorize")
async def vectorize(request: TextRequest):
    vector = text2vec(request.text)
    return {"vector": vector}

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=5000)
