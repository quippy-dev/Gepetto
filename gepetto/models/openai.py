import functools
import re
import threading
from types import SimpleNamespace

import httpx as _httpx
import ida_kernwin
import openai

from gepetto.models.base import LanguageModel
from gepetto.models.oai_responses_base import OAIResponsesAPI
import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

GPT_5_MODEL_NAME = "gpt-5"
GPT_5_MINI_MODEL_NAME = "gpt-5-mini"
GPT_5_NANO_MODEL_NAME = "gpt-5-nano"
GPT_5_HIGH_ALIAS = "gpt-5 (high)"
GPT4_MODEL_NAME = "gpt-4-turbo"
GPT4O_MODEL_NAME = "gpt-4o"
GPTO4_MINI_MODEL_NAME = "o4-mini"
GPT41_MODEL_NAME = "gpt-4.1"
GPTO3_MODEL_NAME = "o3"
GPTO3_MINI_MODEL_NAME = "o3-mini"
OPENAI_RESTRICTED_MODELS = [GPT_5_MODEL_NAME, GPT_5_MINI_MODEL_NAME, GPT_5_NANO_MODEL_NAME, GPTO3_MODEL_NAME]

class OpenAIResponses(OAIResponsesAPI):
    oai_restricted_models = OPENAI_RESTRICTED_MODELS

    def __init__(self, model):
        super().__init__(model)
        self.model = model
        self.api_model = GPT_5_MODEL_NAME if model == GPT_5_HIGH_ALIAS else model
        self.reasoning_effort_override = "high" if model == GPT_5_HIGH_ALIAS else None

    def _make_client(self) -> openai.OpenAI:
        api_key = gepetto.config.get_config("OpenAI", "API_KEY", "OPENAI_API_KEY")
        if not api_key:
            raise ValueError(_("Please edit the configuration file to insert your {api_provider} API key!")
                             .format(api_provider="OpenAI"))

        proxy = gepetto.config.get_config("Gepetto", "PROXY")
        base_url = gepetto.config.get_config("OpenAI", "BASE_URL", "OPENAI_BASE_URL")

        return openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=_httpx.Client(
                proxy=proxy,
            ) if proxy else None
        )

    def query_model(self, query, cb, stream=False, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}

        if isinstance(query, str):
            conversation = [{"role": "user", "content": query}]
        else:
            conversation = list(query)

        try:
            ptc_opt = None
            if isinstance(additional_model_options, dict):
                ptc_opt = additional_model_options.get("parallel_tool_calls")
            if ptc_opt is None:
                cfg = gepetto.config.get_config("OpenAI", "PARALLEL_TOOL_CALLS", default="false")
                ptc_enabled = str(cfg).strip().lower() in ("1", "true", "yes", "on")
            else:
                ptc_enabled = bool(ptc_opt)
        except Exception:
            ptc_enabled = False
        if ptc_enabled:
            hint = (
                "Parallel tool calls are enabled. You may issue multiple read-only tools in parallel (e.g., get_disasm, get_bytes, list_strings, search, list_symbols, get_xrefs/callers/callees, get_metadata). "
                "Do NOT parallelize any write operations (rename_*, set_*, create_*, delete_*, declare_c_type, set_function_prototype, patch_*, dbg_*); sequence those strictly."
            )
            conversation.insert(0, {"role": "system", "content": hint})

        opts = dict(additional_model_options or {})

        if self.api_model and str(self.api_model).startswith("gpt-5"):
            if "temperature" in opts and opts["temperature"] not in (None, 1):
                opts["temperature"] = 1

        try:
            rs_mode = gepetto.config.get_config("OpenAI", "REASONING_SUMMARY", default="off")
        except Exception:
            rs_mode = "off"
        if isinstance(rs_mode, str) and rs_mode.lower() in {"auto", "concise", "detailed"}:
            if str(self.api_model).startswith("gpt-5") or str(self.api_model).startswith("o"):
                if "reasoning" not in opts:
                    effort = "medium" if rs_mode != "detailed" else "high"
                    opts["reasoning"] = {"summary": rs_mode.lower(), "effort": effort}

        if self.reasoning_effort_override:
            r = opts.get("reasoning", {}) if isinstance(opts.get("reasoning"), dict) else {}
            r["effort"] = self.reasoning_effort_override
            opts["reasoning"] = r

        if self.oai_org_unverified:
            opts.pop("reasoning", None)

        return self._query_via_responses(conversation, cb, stream, opts)

    @staticmethod
    def get_menu_name() -> str:
        return "OpenAI (Responses)"

    @staticmethod
    def supported_models():
        return [
            GPT_5_HIGH_ALIAS,
            GPT_5_MODEL_NAME,
            GPT_5_MINI_MODEL_NAME,
            GPT_5_NANO_MODEL_NAME,
            GPT4_MODEL_NAME,
            GPT4O_MODEL_NAME,
            GPTO4_MINI_MODEL_NAME,
            GPT41_MODEL_NAME,
            GPTO3_MODEL_NAME,
            GPTO3_MINI_MODEL_NAME
        ]

    @staticmethod
    def is_configured_properly() -> bool:
        return bool(gepetto.config.get_config("OpenAI", "API_KEY", "OPENAI_API_KEY"))

class GPT(LanguageModel):
    """
    This class is a temporary shim for backward compatibility.
    It will be removed in a future version.
    """
    def __init__(self, model):
        print("Warning: The 'GPT' class is deprecated and will be removed in a future version. Please use 'OpenAIResponses' instead.")
        self.delegate = OpenAIResponses(model)

    def query_model_async(self, query, cb, stream=False, additional_model_options=None):
        return self.delegate.query_model_async(query, cb, stream, additional_model_options)

    def cancel_current_request(self) -> None:
        return self.delegate.cancel_current_request()

    @staticmethod
    def supported_models() -> list[str]:
        return OpenAIResponses.supported_models()

    @staticmethod
    def get_menu_name() -> str:
        return "OpenAI"

    @staticmethod
    def is_configured_properly() -> bool:
        return OpenAIResponses.is_configured_properly()

gepetto.models.model_manager.register_model(OpenAIResponses)
gepetto.models.model_manager.register_model(GPT)
