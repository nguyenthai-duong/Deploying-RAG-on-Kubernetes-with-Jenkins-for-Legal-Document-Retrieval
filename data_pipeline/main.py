import base64
import fitz  # PyMuPDF
import re
import json
import os
import requests
from google.cloud import storage
from langchain.text_splitter import RecursiveCharacterTextSplitter

json_bucket_name = os.environ.get('JSON_BUCKET_NAME')

# Remove redundant spaces from the text.
def remove_space_redundant(text):
    words = text.split()
    clean_text = " ".join(words)
    return clean_text

# Extract text from a PDF file located at the given file path.
def get_text_from_pdf(file_path):
    doc = fitz.open(file_path)
    text = ""
    for page in doc:
        text += page.get_text()
    return text

# Create a structured JSON from the extracted text, splitting content into chunks.
def create_chunk_json(text):
    content_between_chapters = re.findall(r"(Chương \b(?:I{1,3}(?:V?X?)?|VI{0,3}|XI{0,3}V?|XVI{0,3})\b\.?)(.*?)(?=(Chương \b(?:I{1,3}(?:V?X?)?|VI{0,3}|XI{0,3}V?|XVI{0,3})\b\.? |$))", text, re.DOTALL)
    chapter_name = []
    content_chapter = []
    all_content_chapter = []
    for content_between_chapter in content_between_chapters:
        chapter_name_temp = content_between_chapter[0].strip()
        content_chapter_temp = content_between_chapter[1].strip()
        chapter_name.append(chapter_name_temp.strip())
        content_chapter.append(content_chapter_temp.strip())
        all_content_chapter.append(content_between_chapter[0] + content_between_chapter[1])

    chapter_title = []
    rule_title = []
    contents = []
    regex_chapter = re.compile(r'(Chương \b(?:I{1,3}(?:V?X?)?|VI{0,3}|XI{0,3}V?|XVI{0,3})\b\.?)\s*(.*)')
    regex_rule = re.compile(r'(Điều \d+\.)(.*?)(?=(Điều \d+\. |$))', re.DOTALL)
    for content_chap in all_content_chapter:
        matches_chapter = regex_chapter.findall(content_chap)
        matches_rule = regex_rule.findall(content_chap)
        for match_rule in matches_rule:
            for match_chapter in matches_chapter:
                temp = match_chapter[0] + "\n" + match_chapter[1]
                chapter_title.append(temp.strip())
            temp_title_rule = match_rule[0] + match_rule[1].split('\n')[0].strip()
            rule_title.append(temp_title_rule.strip())
            temp_content_rule = remove_space_redundant(" ".join(match_rule[1].split('\n')[1:]).strip())
            contents.append(temp_content_rule)

    titles = []
    for i in range(len(chapter_title)):
        titles.append("Document Title" + "\n" + chapter_title[i] + "\n" + rule_title[i])

    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=512,
        chunk_overlap=64)

    title_chunk, chunks = [], []
    for i in range(len(contents)):
        chunk = text_splitter.split_text(contents[i])

        num = len(chunk)
        for k in range(num):
            title_chunk.append(titles[i])
        chunks.append(chunk)

    chunks = [item for chunk in chunks for item in chunk]

    data = []
    for i in range(len(title_chunk)):
        data.append({'title': title_chunk[i], 'context': chunks[i]})

    return data

# Download a blob from Google Cloud Storage to a temporary local path.
def download_blob_to_tmp(blob, file_name):
    temp_path = f"/tmp/{file_name}"
    blob.download_to_filename(temp_path)
    return temp_path

# Combine text content from multiple PDFs in a GCS bucket, excluding a specified file.
def combine_texts_from_pdfs(bucket, exclude_file=None):
    all_text = ""
    blobs = bucket.list_blobs()
    for blob in blobs:
        if blob.name.endswith('.pdf') and blob.name != exclude_file:
            temp_pdf_path = download_blob_to_tmp(blob, blob.name)
            text = get_text_from_pdf(temp_pdf_path)
            all_text += text + "\n"
    return all_text

# Upload a JSON object to a specified Google Cloud Storage bucket.
def upload_json_to_bucket(json_data, bucket_name, output_filename):
    storage_client = storage.Client()
    json_bucket = storage_client.bucket(bucket_name)
    output_blob = json_bucket.blob(output_filename)

    output_json_path = f"/tmp/{output_filename}"
    with open(output_json_path, "w", encoding="utf-8") as file:
        json.dump(json_data, file, ensure_ascii=False, indent=4)
    
    output_blob.upload_from_filename(output_json_path)
    return output_json_path

# Send a file to a remote API using an HTTP POST request.
def send_file_to_api(file_path):
    api_url = os.environ.get('API_URL')
    with open(file_path, 'rb') as file:
        files = {'file': file}
        response = requests.post(api_url, files=files)
        if response.status_code != 200:
            print(f"Failed to send file to API. Status code: {response.status_code}")
        else:
            print(f"Successfully sent file to API.")

# Process a PDF file uploaded to a GCS bucket and generate a combined JSON output.
def process_pdf_file(event, context):
    """Triggered by a Pub/Sub message when a file is uploaded."""
    pubsub_message = base64.b64decode(event['data']).decode('utf-8')
    message_data = json.loads(pubsub_message)

    if 'bucket' not in message_data or 'name' not in message_data:
        print("Missing 'bucket' or 'name' in Pub/Sub message")
        return

    file_name = message_data['name']

    # Only proceed if the file is a PDF
    if not file_name.endswith('.pdf'):
        print(f"File {file_name} is not a PDF. Skipping processing.")
        return

    bucket_name = message_data['bucket']
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(file_name)

    # Download the uploaded PDF file from GCS
    temp_pdf_path = download_blob_to_tmp(blob, file_name)

    # Extract text from the PDF and create a JSON
    text = get_text_from_pdf(temp_pdf_path)
    current_file_json = create_chunk_json(text)

    # Process all other PDFs in the bucket and generate a combined JSON
    all_text = combine_texts_from_pdfs(bucket, exclude_file=file_name)
    other_files_json = create_chunk_json(all_text)

    combined_json = current_file_json + other_files_json

    # Save combined result to 'all.json' in the new bucket
    output_json_path = upload_json_to_bucket(combined_json, json_bucket_name, 'all.json')

    print(f"Processed {file_name} and saved combined result to {json_bucket_name}/all.json")

    # Send the all.json file to the API
    send_file_to_api(output_json_path)

# Handle deletion of a PDF file in GCS by regenerating combined JSON without the deleted file.
def handle_pdf_delete(event, context):
    """Triggered by a Pub/Sub message."""
    try:
        # Decode the Pub/Sub message
        pubsub_message = base64.b64decode(event['data']).decode('utf-8')
        message_data = json.loads(pubsub_message)
        
        # Access the bucket name and file name
        deleted_file_name = message_data['name']
        bucket_name = message_data['bucket']

        print(f"Deleted file: {deleted_file_name} from bucket: {bucket_name}")

        # Your existing code here to process the deletion
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)

        # Re-generate the all.json by processing all remaining PDFs
        all_text = combine_texts_from_pdfs(bucket)
        updated_json = create_chunk_json(all_text)

        # Save updated JSON to the new bucket
        output_json_path = upload_json_to_bucket(updated_json, json_bucket_name, 'all.json')

        print(f"Updated {json_bucket_name}/all.json after deleting {deleted_file_name}")
        send_file_to_api(output_json_path)

    except KeyError as e:
        print(f"KeyError - reason: {str(e)}")
    except Exception as e:
        print(f"Error processing file deletion: {str(e)}")
