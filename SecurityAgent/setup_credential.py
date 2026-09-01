import os

import boto3

client = boto3.client("bedrock-agentcore-control", region_name="us-west-2")

response = client.create_api_key_credential_provider(
    name="gemini-api-key",
    apiKey=os.environ["GEMINI_API_KEY"],
)

print(response)