import functools
import threading
from types import SimpleNamespace

import httpx as _httpx
import ida_kernwin
import ollama

from gepetto.models.oai_chat_base import OAIChatAPI
import gepetto.models.model_manager
import gepetto.config

_ = gepetto.config._

OLLAMA_MODELS = None

class Ollama(OAIChatAPI):
    @staticmethod
    def get_menu_name() -> str:
        return "Ollama"

    def _make_client(self) -> ollama.Client:
        host = gepetto.config.get_config("Ollama", "HOST", None, "http://localhost:11434")
        return ollama.Client(host=host)

    @staticmethod
    def supported_models():
        global OLLAMA_MODELS
        if OLLAMA_MODELS is None:
            try:
                host = gepetto.config.get_config("Ollama", "HOST", None, "http://localhost:11434")
                client = ollama.Client(host=host, timeout=2)
                OLLAMA_MODELS = [m["model"] for m in client.list()["models"]]
            except (_httpx.ConnectError, _httpx.ConnectTimeout, ollama.ResponseError, ConnectionError):
                OLLAMA_MODELS = []
        return OLLAMA_MODELS

    @staticmethod
    def is_configured_properly() -> bool:
        return len(Ollama.supported_models()) > 0

    def __str__(self):
        return self.model

    def __init__(self, model):
        super().__init__(model)
        self.model = model

    def _query_via_chat_completions(self, conversation, cb, stream, additional_model_options):
        kwargs = {}
        if "response_format" in additional_model_options and additional_model_options["response_format"]["type"] == "json_object":
            kwargs["format"] = "json"

        opts = dict(additional_model_options or {})
        opts.pop("tools", None)

        try:
            response = self.client.chat(model=self.model,
                                        messages=conversation,
                                        stream=stream,
                                        options=opts,
                                        **kwargs)
            if not stream:
                pseudo = SimpleNamespace(output=[{"type": "output_text", "content": [{"text": response["message"]["content"]}]}])
                cb(response=pseudo)
            else:
                with self._cancel_lock:
                    self._cancel_ev = getattr(self, "_cancel_ev", None) or threading.Event()
                    self._active_stream_ctx = response

                text_buf = []
                for chunk in response:
                    if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                        try:
                            close = getattr(response, "close", None)
                            if callable(close):
                                close()
                        except Exception:
                            pass
                        with self._cancel_lock:
                            self._active_stream_ctx = None
                        break

                    dtext = chunk['message']['content']
                    text_buf.append(dtext)
                    cb(dtext, None)

                if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                    with self._cancel_lock:
                        self._active_stream_ctx = None
                    return

                final_text = "".join(text_buf)
                pseudo = SimpleNamespace(output=[{"type": "output_text", "content": [{"text": final_text}]}])
                cb(response=pseudo)
                with self._cancel_lock:
                    self._active_stream_ctx = None
        except Exception as e:
            print(e)

gepetto.models.model_manager.register_model(Ollama)
