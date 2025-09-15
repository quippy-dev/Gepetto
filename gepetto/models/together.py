import together

import gepetto.config
import gepetto.models.model_manager
from gepetto.models.oai_chat_base import OAIChatAPI

_ = gepetto.config._

MISTRAL_MODEL_NAME = "mistralai/Mixtral-8x22B-Instruct-v0.1"

class Together(OAIChatAPI):
    @staticmethod
    def get_menu_name() -> str:
        return "Together"

    @staticmethod
    def supported_models():
        return [MISTRAL_MODEL_NAME]

    @staticmethod
    def is_configured_properly() -> bool:
        return bool(gepetto.config.get_config("Together", "API_KEY", "TOGETHER_API_KEY"))

    def __init__(self, model):
        super().__init__(model)
        self.model = model

    def _make_client(self) -> together.Together:
        api_key = gepetto.config.get_config("Together", "API_KEY", "TOGETHER_API_KEY")
        if not api_key:
            raise ValueError(_("Please edit the configuration file to insert your {api_provider} API key!")
                             .format(api_provider="Together"))

        base_url = gepetto.config.get_config("Together", "BASE_URL", "TOGETHER_BASE_URL")

        return together.Together(
            api_key=api_key,
            base_url=base_url)

    def query_model(self, query, cb, stream=False, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}

        if "tools" in additional_model_options:
            from gepetto.ida.tools.schemas import get_tools_for_provider
            additional_model_options["tools"] = get_tools_for_provider("oai_chat")

        return self._query_via_chat_completions(query, cb, stream, additional_model_options)

gepetto.models.model_manager.register_model(Together)
