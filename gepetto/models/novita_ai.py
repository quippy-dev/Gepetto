import openai
import httpx as _httpx

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.oai_chat_base import OAIChatAPI

_ = gepetto.config._

NOVITA_MODELS = [
  "deepseek/deepseek-r1",
  "deepseek/deepseek_v3",
  "meta-llama/llama-3.3-70b-instruct",
  "meta-llama/llama-3.1-70b-instruct",
  "meta-llama/llama-3.1-405b-instruct",
]

class NovitaAI(OAIChatAPI):
    @staticmethod
    def get_menu_name() -> str:
        return "Novita AI"

    @staticmethod
    def supported_models():
        return NOVITA_MODELS

    @staticmethod
    def is_configured_properly() -> bool:
        return bool(gepetto.config.get_config("NovitaAI", "API_KEY", "NOVITAAI_API_KEY"))

    def __init__(self, model):
        super().__init__(model)
        self.model = model

    def _make_client(self) -> openai.OpenAI:
        api_key = gepetto.config.get_config("NovitaAI", "API_KEY", "NOVITAAI_API_KEY")
        if not api_key:
            print(_("Please edit the configuration file to insert your {api_provider} API key!")
                  .format(api_provider="Novita AI"))
            raise ValueError(_("No valid Novita AI API key found"))

        proxy = gepetto.config.get_config("Gepetto", "PROXY")

        return openai.OpenAI(
            api_key=api_key,
            base_url="https://api.novita.ai/v3/openai",
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

gepetto.models.model_manager.register_model(NovitaAI)
