import openai
import json
import httpx as _httpx

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.oai_chat_base import OAIChatAPI

_ = gepetto.config._

DEFAULT_MODELS = [
    "deepseek-ai/DeepSeek-R1",
    "deepseek-ai/DeepSeek-V3",
    "deepseek-ai/DeepSeek-V3-0324",
    "google/gemma-3-27b-it",
    "klusterai/Meta-Llama-3.1-8B-Instruct-Turbo",
    "klusterai/Meta-Llama-3.1-405B-Instruct-Turbo",
    "klusterai/Meta-Llama-3.3-70B-Instruct-Turbo",
    "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8",
    "meta-llama/Llama-4-Scout-17B-16E-Instruct",
    "Qwen/Qwen2.5-VL-7B-Instruct"
]

class Kluster(OAIChatAPI):
    @staticmethod
    def get_menu_name() -> str:
        return "Kluster.ai"

    @staticmethod
    def supported_models():
        config_models = gepetto.config.get_config("Kluster", "MODELS")
        if config_models:
            try:
                return json.loads(config_models)
            except json.JSONDecodeError:
                return [model.strip() for model in config_models.split(",")]
        return DEFAULT_MODELS

    @staticmethod
    def is_configured_properly() -> bool:
        return bool(gepetto.config.get_config("Kluster", "API_KEY"))

    def __init__(self, model):
        super().__init__(model)
        self.model = model

    def _make_client(self) -> openai.OpenAI:
        api_key = gepetto.config.get_config("Kluster", "API_KEY")
        if not api_key:
            raise ValueError(
                _("Please edit the configuration file to insert your {api_provider} API key!")
                .format(api_provider=self.get_menu_name()))

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("Kluster", "BASE_URL",
                                           None,
                                           "https://api.kluster.ai/v1")

        return openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(proxy=proxy) if proxy else None)

gepetto.models.model_manager.register_model(Kluster) 