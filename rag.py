from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings


# 1. Load your notes (folder containing .md or .txt files)
loader = DirectoryLoader('./htb_notes/', glob="**/*.md", loader_cls=TextLoader,
                         loader_kwargs={"encoding": "utf-8"},recursive=True)
docs = loader.load()

# 2. Split the texts into clean chunks
text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
chunks = text_splitter.split_documents(docs)

# 3. Create the local vector store
vectorstore = Chroma.from_documents(chunks, embedding=HuggingFaceEmbeddings(model_name="BAAI/bge-m3"), persist_directory="./chroma_db")