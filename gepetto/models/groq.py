import groq
import httpx as _httpx

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.oai_chat_base import OAIChatAPI

_ = gepetto.config._

LLAMA_31_MODEL_NAME = "llama-3.1-70b-versatile"
LLAMA_32_MODEL_NAME = "llama-3.2-90b-text-preview"
MIXTRAL_MODEL_NAME = "mixtral-8x7b-32768"

class Groq(OAIChatAPI):
    @staticmethod
    def get_menu_name() -> str:
        return "Groq"

    @staticmethod
    def supported_models():
        return [LLAMA_31_MODEL_NAME, LLAMA_32_MODEL_NAME, MIXTRAL_MODEL_NAME]

    @staticmethod
    def is_configured_properly() -> bool:
        return bool(gepetto.config.get_config("Groq", "API_KEY", "GROQ_API_KEY"))

    def __init__(self, model):
        super().__init__(model)
        self.model = model

    def _make_client(self) -> groq.Groq:
        api_key = gepetto.config.get_config("Groq", "API_KEY", "GROQ_API_KEY")
        if not api_key:
            raise ValueError(_("Please edit the configuration file to insert your {api_provider} API key!")
                             .format(api_provider="Groq"))

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("Groq", "BASE_URL", "GROQ_BASE_URL")

        return groq.Groq(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(
                proxy=proxy,
            ) if proxy else None
        )

    def query_model(self, query, cb, stream=False, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}

        if "tools" in additional_model_options:
            from gepetto.ida.tools.schemas import get_tools_for_provider
            additional_model_options["tools"] = get_tools_for_provider("oai_chat")

        return self._query_via_chat_completions(query, cb, stream, additional_model_options)

gepetto.models.model_manager.register_model(Groq)
