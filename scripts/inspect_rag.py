from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma

embeddings = HuggingFaceEmbeddings(model_name="BAAI/bge-m3")
vectorstore = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)

# 1. Test with a scored search (to see the distances)
query = "DCSync"
print(f"Raw search for: '{query}'")
results = vectorstore.similarity_search_with_score(query, k=3)

for doc, score in results:
    print(f"\n[Distance score: {score:.4f}]")
    print(doc.page_content[:300] + "...")

# 2. If that returns nothing, do a simple text lookup on the first 3 documents in the store
print("\n--- Preview of the first chunk's content in the store ---")
all_docs = vectorstore.get(limit=3)
if all_docs and 'documents' in all_docs and all_docs['documents']:
    print(all_docs['documents'][0][:400])