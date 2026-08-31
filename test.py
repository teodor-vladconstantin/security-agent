import os
from dotenv import load_dotenv
from strands import Agent
from strands.models.gemini import GeminiModel
from tools import scan_for_secrets, scan_dependencies

load_dotenv()

model = GeminiModel(
    client_args={"api_key": os.getenv("GEMINI_API_KEY")},
    model_id="gemini-3.6-flash",
)

agent = Agent(
    model=model,
    tools=[scan_for_secrets, scan_dependencies],
    system_prompt=(
        "You are a security assistant. When asked to check a repository, "
        "use scan_for_secrets and scan_dependencies as needed. "
        "Flag anything that looks like a real, live credential as CRITICAL. "
        "For dependency vulnerabilities, flag HIGH/CRITICAL severity CVEs "
        "as urgent, and note LOW/MEDIUM ones as things that can wait. "
        "Ignore false positives (class names, example values, placeholder text)."
    ),
)

agent("Check this project for exposed secrets and vulnerable dependencies. Give me a prioritized summary.")