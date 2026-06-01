# CLEAN: same retrieval, but a human-approval mediation step gates execution.
# The mediation token between source and sink suppresses the finding.
import os

docs = retriever.get_relevant_documents(user_query)
cmd = docs[0].page_content
if human_in_the_loop_approve(cmd):
    os.system(cmd)
