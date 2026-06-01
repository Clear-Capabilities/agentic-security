# VULNERABLE: a retrieved (RAG) document body is executed as a shell command.
# A poisoned document in the vector store → command execution (indirect prompt
# injection → excessive agency).
import os
from langchain.vectorstores import FAISS

retriever = vectorstore.as_retriever()
docs = retriever.get_relevant_documents(user_query)
os.system(docs[0].page_content)
