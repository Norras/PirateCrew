from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings


# 1. Charger vos cours (dossier contenant des .md ou .txt)
loader = DirectoryLoader('./htb_notes/', glob="**/*.md", loader_cls=TextLoader,
                         loader_kwargs={"encoding": "utf-8"},recursive=True)
docs = loader.load()

# 2. Découper les textes en morceaux propres
text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
chunks = text_splitter.split_documents(docs)

# 3. Créer la base vectorielle locale
vectorstore = Chroma.from_documents(chunks, embedding=HuggingFaceEmbeddings(model_name="BAAI/bge-m3"), persist_directory="./chroma_db")