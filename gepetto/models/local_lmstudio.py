import httpx as _httpx
from gepetto.models.oai_chat_base import OAIChatAPI
import openai

import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

LMSTUDIO_MODELS = None

class LMStudio(OAIChatAPI):
    @staticmethod
    def get_menu_name() -> str:
        return "LM Studio"

    @staticmethod
    def supported_models() -> list:
        global LMSTUDIO_MODELS

        if LMSTUDIO_MODELS is not None:
            return LMSTUDIO_MODELS

        base_url = gepetto.config.get_config("LMStudio", "BASE_URL", None, "http://127.0.0.1:1234/v1/")
        try:
            response = _httpx.get(f"{base_url}models", timeout=2)
            if response.status_code == 200:
                data = response.json().get("data", [])
                LMSTUDIO_MODELS = [model["id"] for model in data]
            else:
                print(_("Failed to fetch models from {base_url}: {status_code}").format(
                    base_url=base_url, status_code=response.status_code
                ))
                LMSTUDIO_MODELS = []
        except (_httpx.ConnectError, _httpx.ConnectTimeout):
            LMSTUDIO_MODELS = []

        return LMSTUDIO_MODELS

    @staticmethod
    def is_configured_properly() -> bool:
        return len(LMStudio.supported_models()) > 0

    def __init__(self, model):
        super().__init__(model)
        self.model = model

    def _make_client(self) -> openai.OpenAI:
        base_url = gepetto.config.get_config("LMStudio", "BASE_URL", None, "http://127.0.0.1:1234/v1/")
        proxy = gepetto.config.get_config("Gepetto", "PROXY")

        return openai.OpenAI(
            api_key="NO_API_KEY",
            base_url=base_url,
            http_client=_httpx.Client(
                proxy=proxy,
            ) if proxy else None
        )

    def query_model_async(self, query, cb, stream=False, additional_model_options=None):
        if additional_model_options is not None and additional_model_options.get("response_format", {}).get("type") == "json_object":
            additional_model_options.update({
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "schema": {
                            "type": "object"
                        }
                    }
                }
            })
        else:
            additional_model_options = {}

        if "tools" in additional_model_options:
            from gepetto.ida.tools.schemas import get_tools_for_provider
            additional_model_options["tools"] = get_tools_for_provider("oai_chat")

        super().query_model_async(query, cb, stream, additional_model_options)

gepetto.models.model_manager.register_model(LMStudio)
