In this POC we are planning to build the the system for healthcare system / hospital.

there will be two end api endpoints :

- /upload
- /chat

In upload api the user will be upload the doc. then we will check the consent, authorization etc. in short we will run input guardrails. If everything is fine then we will save the doc in the database. We will then call the RAG module and they will save database.

In chat api, the user will ask the question on doc with or without docs. then we have to run the input / egress guardrails and verify all the security and pass the chat and doc if passed with doc to D3 module.
Then we will close the api. Then we will start the streaming like chat gpt if the response is coming from.
while the response is coming then we have to validate it using output guardrails / egress guardrails.

You have the all the files related to my POC.


