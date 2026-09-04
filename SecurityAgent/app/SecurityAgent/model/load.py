import os

from strands.models import BedrockModel
from strands.models.gemini import GeminiModel
from bedrock_agentcore.identity.auth import requires_api_key

IDENTITY_PROVIDER_NAME = "gemini-api-key"
IDENTITY_ENV_VAR = "GEMINI_API_KEY"
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-5")


@requires_api_key(provider_name=IDENTITY_PROVIDER_NAME)
def _agentcore_identity_api_key_provider(api_key: str) -> str:
    """Fetch API key from AgentCore Identity."""
    return api_key


def _get_api_key() -> str:
    """
    Uses AgentCore Identity for API key management in deployed environments.
    For local development, run via 'agentcore dev' which loads agentcore/.env.
    """
    if os.getenv("LOCAL_DEV") == "1":
        api_key = os.getenv(IDENTITY_ENV_VAR)
        if not api_key:
            raise RuntimeError(
                f"{IDENTITY_ENV_VAR} not found. Add {IDENTITY_ENV_VAR}=your-key to .env.local"
            )
        return api_key
    return _agentcore_identity_api_key_provider()


def load_model():
    """Get the configured model client.

    MODEL_PROVIDER=bedrock (default) uses AWS Bedrock via the runtime's IAM
    role - no API key needed, already granted bedrock:InvokeModel by the
    AgentCore CDK construct. Set MODEL_PROVIDER=gemini to use Gemini instead.
    """
    if os.getenv("MODEL_PROVIDER", "bedrock").lower() == "gemini":
        return GeminiModel(
            client_args={"api_key": _get_api_key()},
            model_id="gemini-3.6-flash",
        )
    return BedrockModel(model_id=BEDROCK_MODEL_ID)
