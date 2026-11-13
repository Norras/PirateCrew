import os
from dotenv import load_dotenv
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_chroma import Chroma
from langchain_anthropic import ChatAnthropic

load_dotenv()

DB_DIR = "./chroma_db"

def charger_base_rag():
    embeddings = HuggingFaceEmbeddings(model_name="BAAI/bge-m3")
    if not os.path.exists(DB_DIR):
        raise FileNotFoundError("La base ChromaDB n'existe pas. Lancez d'abord 'rag.py' !")
    return Chroma(persist_directory=DB_DIR, embedding_function=embeddings)

def interroger_agent_rag(question: str):
    vectorstore = charger_base_rag()
    docs = vectorstore.similarity_search(question, k=3)
    
    contexte = "\n\n---\n\n".join([doc.page_content for doc in docs])

    llm = ChatAnthropic(
        model="claude-sonnet-4-6"
    )

    prompt = f"""Tu es un assistant expert en cybersécurité et pentest.
Utilise **exclusivement** la documentation fournie ci-dessous pour répondre à la question de l'utilisateur. 
Si la réponse ne se trouve pas dans la documentation, indique-le clairement.

=== DOCUMENTATION SOURCE (RAG) ===
{contexte}

=== QUESTION ===
{question}
"""

    print("Envoi de la requête à Claude avec le contexte RAG...\n")
    reponse = llm.invoke(prompt)
    
    # Gestion sécurisée des métadonnées
    meta = getattr(reponse, 'response_metadata', {}) or {}
    stop_reason = meta.get('stop_reason')
    
    if stop_reason == 'refusal' or not reponse.content:
        print("[!] Alerte : Claude a bloqué la génération (filtrage de sécurité actif).")
        return "Réponse bloquée par les filtres de sécurité du modèle."

    return reponse.content

if __name__ == "__main__":
    ma_question = "Explique le fonctionnement du protocole DCSync dans l'Active Directory d'après les documents."
    
    resultat = interroger_agent_rag(ma_question)
    
    print("=== RÉPONSE DE CLAUDE ===")
    print(resultat)