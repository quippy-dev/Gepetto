import openai
import json
import httpx as _httpx

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.oai_chat_base import OAIChatAPI

_ = gepetto.config._

DEFAULT_SILICONFLOW_MODELS = [
    "deepseek-ai/DeepSeek-V3",
    "deepseek-ai/DeepSeek-R1",
    "Pro/deepseek-ai/DeepSeek-V3",
    "Pro/deepseek-ai/DeepSeek-R1",
    "Qwen/Qwen2.5-72B-Instruct-128K",
    "Qwen/Qwen2.5-Coder-32B-Instruct",
    "Qwen/Qwen2.5-Coder-7B-Instruct",
]


class SiliconFlow(OAIChatAPI):

    @staticmethod
    def get_menu_name() -> str:
        return "SiliconFlow"

    @staticmethod
    def supported_models():
        config_models = gepetto.config.get_config("SiliconFlow", "MODELS")
        if config_models:
            try:
                return json.loads(config_models)
            except json.JSONDecodeError:
                return [model.strip() for model in config_models.split(",")]
        return DEFAULT_SILICONFLOW_MODELS

    @staticmethod
    def is_configured_properly() -> bool:
        return bool(
            gepetto.config.get_config("SiliconFlow", "API_KEY",
                                      "SILICONFLOW_API_KEY"))

    def __init__(self, model):
        super().__init__(model)
        self.model = model

    def _make_client(self) -> openai.OpenAI:
        api_key = gepetto.config.get_config("SiliconFlow", "API_KEY",
                                            "SILICONFLOW_API_KEY")
        if not api_key:
            raise ValueError(
                _("Please edit the configuration file to insert your {api_provider} API key!"
                  ).format(api_provider="SiliconFlow"))

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("SiliconFlow", "BASE_URL",
                                             "SILICONFLOW_BASE_URL",
                                             "https://api.siliconflow.cn/v1")

        return openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(proxy=proxy) if proxy else None)

    def query_model(self, query, cb, stream=False, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}

        if "tools" in additional_model_options:
            from gepetto.ida.tools.schemas import get_tools_for_provider
            additional_model_options["tools"] = get_tools_for_provider("oai_chat")

        return self._query_via_chat_completions(query, cb, stream, additional_model_options)

gepetto.models.model_manager.register_model(SiliconFlow)
