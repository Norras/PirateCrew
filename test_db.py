from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma

embeddings = HuggingFaceEmbeddings(model_name="BAAI/bge-m3")
vectorstore = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)

# 1. Test avec une recherche par score (pour voir les distances)
query = "DCSync"
print(f"Recherche brute pour : '{query}'")
results = vectorstore.similarity_search_with_score(query, k=3)

for doc, score in results:
    print(f"\n[Score de distance: {score:.4f}]")
    print(doc.page_content[:300] + "...")

# 2. Si ça ne donne rien, faisons une recherche textuelle simple sur les 3 premiers documents de la base
print("\n--- Aperçu du contenu du premier chunk de la base ---")
all_docs = vectorstore.get(limit=3)
if all_docs and 'documents' in all_docs and all_docs['documents']:
    print(all_docs['documents'][0][:400])