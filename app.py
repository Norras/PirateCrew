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
        raise FileNotFoundError("The ChromaDB database does not exist. Run 'rag.py' first!")
    return Chroma(persist_directory=DB_DIR, embedding_function=embeddings)

def interroger_agent_rag(question: str):
    vectorstore = charger_base_rag()
    docs = vectorstore.similarity_search(question, k=3)
    
    contexte = "\n\n---\n\n".join([doc.page_content for doc in docs])

    llm = ChatAnthropic(
        model="claude-sonnet-4-6"
    )

    prompt = f"""You are an expert assistant in cybersecurity and pentesting.
Use **only** the documentation provided below to answer the user's question.
If the answer is not in the documentation, say so clearly.

=== SOURCE DOCUMENTATION (RAG) ===
{contexte}

=== QUESTION ===
{question}
"""

    print("Sending the request to Claude with the RAG context...\n")
    reponse = llm.invoke(prompt)

    # Safe handling of metadata
    meta = getattr(reponse, 'response_metadata', {}) or {}
    stop_reason = meta.get('stop_reason')
    
    if stop_reason == 'refusal' or not reponse.content:
        print("[!] Warning: Claude blocked the generation (safety filtering active).")
        return "Response blocked by the model's safety filters."

    return reponse.content

if __name__ == "__main__":
    ma_question = "Explain how the DCSync protocol works in Active Directory, based on the documents."

    resultat = interroger_agent_rag(ma_question)

    print("=== CLAUDE'S RESPONSE ===")
    print(resultat)