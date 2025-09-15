import abc
import threading
from types import SimpleNamespace

import httpx as _httpx
import openai

from gepetto.models.base import LanguageModel
import gepetto.config

_ = gepetto.config._

class OAIChatAPI(LanguageModel):
    def __init__(self, model_name):
        self.model_name = model_name
        self.api_model = model_name
        self.client = self._make_client()
        self._cancel_lock = threading.Lock()
        self._cancel_ev: threading.Event | None = None
        self._active_stream_ctx = None
        self._fallback_notice_sent = False

    @abc.abstractmethod
    def _make_client(self) -> openai.OpenAI:
        """
        Subclasses must implement this to return a configured OpenAI client.
        """
        pass

    def _build_chat_request_args(self, messages, tools, opts):
        """
        Produce arguments for client.chat.completions.create.
        """
        return {
            "model": self.api_model,
            "messages": messages,
            "tools": tools,
            **opts,
        }

    def _finalize_to_envelope(self, text: str, tool_calls: list[dict]):
        """
        Produce a stable ResultEnvelope for UI/CLI consumption.
        """
        output = []
        if text:
            output.append({
                "type": "output_text",
                "content": [{"text": text}],
            })
        for tc in tool_calls or []:
            output.append({
                "type": "tool_call",
                "id": tc.get("id", ""),
                "name": tc.get("function", {}).get("name", ""),
                "arguments": tc.get("function", {}).get("arguments", ""),
            })
        return SimpleNamespace(output=output)

    def _query_via_chat_completions(self, conversation, cb, stream, additional_model_options):
        messages = conversation
        opts = dict(additional_model_options or {})
        tools = opts.pop("tools", None)

        if "parallel_tool_calls" not in opts:
            try:
                ptc = gepetto.config.get_config("OpenAI", "PARALLEL_TOOL_CALLS", default="false")
                ptc_bool = str(ptc).strip().lower() in ("1", "true", "yes", "on")
            except Exception:
                ptc_bool = False
            opts["parallel_tool_calls"] = ptc_bool

        rf = opts.get("response_format")
        if isinstance(rf, dict) and rf.get("type") == "json_object":
            opts["response_format"] = {"type": "json_object"}

        def _emit_fallback_notice(why: str, disable_reasoning: bool = True):
            try:
                msg = _(
                    "Streaming fallback: {why}. Switching to non‑streaming mode. Latency may be higher; reasoning summaries will be disabled."
                ).format(why=str(why)) if disable_reasoning else _(
                    "Streaming fallback: {why}. Switching to non‑streaming mode. Latency may be higher."
                ).format(why=str(why))
                cb({"status": "fallback", "text": msg}, None)
            except Exception:
                pass

        def _fallback_chat_no_stream():
            opts_local = dict(opts)
            opts_local.pop("reasoning", None)
            try:
                request_args = self._build_chat_request_args(messages, tools, opts_local)
                resp = self.client.chat.completions.create(stream=False, **request_args)
            except Exception as _e:
                print(_("Exception encountered while retrying without streaming: {error}").format(error=str(_e)))
                return

            choice = resp.choices[0] if getattr(resp, "choices", None) else None
            text = (getattr(choice.message, "content", None) if choice else None) or ""
            tcs = getattr(choice.message, "tool_calls", None) or []
            if text:
                try:
                    cb(text, None)
                except Exception:
                    pass
            pseudo = self._finalize_to_envelope(text, tcs)
            try:
                cb(response=pseudo)
            except Exception:
                pass

        try:
            request_args = self._build_chat_request_args(messages, tools, opts)
            if not stream:
                resp = self.client.chat.completions.create(**request_args)
                choice = resp.choices[0] if getattr(resp, "choices", None) else None
                text = (getattr(choice.message, "content", None) if choice else None) or ""
                tcs = getattr(choice.message, "tool_calls", None) or []
                pseudo = self._finalize_to_envelope(text, tcs)
                cb(response=pseudo)
                return
            else:
                stream_resp = self.client.chat.completions.create(stream=True, **request_args)
                with self._cancel_lock:
                    self._cancel_ev = getattr(self, "_cancel_ev", None) or threading.Event()
                    self._active_stream_ctx = stream_resp

                text_buf = []
                tool_calls = {}
                def upsert_tool_call(delta_tc):
                    idx = getattr(delta_tc, "index", None)
                    if idx is None:
                        return
                    entry = tool_calls.get(idx)
                    if not entry:
                        entry = {"id": getattr(delta_tc, "id", "") or "",
                                 "function": {"name": "", "arguments": ""}}
                        tool_calls[idx] = entry
                    fn = getattr(delta_tc, "function", None)
                    if fn is not None:
                        name = getattr(fn, "name", None)
                        args = getattr(fn, "arguments", None)
                        if name:
                            entry["function"]["name"] += name
                        if args:
                            entry["function"]["arguments"] += args

                for chunk in stream_resp:
                    if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                        try:
                            close = getattr(stream_resp, "close", None)
                            if callable(close):
                                close()
                        except Exception:
                            pass
                        with self._cancel_lock:
                            self._active_stream_ctx = None
                        break

                    ch = chunk.choices[0] if getattr(chunk, "choices", None) else None
                    delta = getattr(ch, "delta", None)
                    if delta is None:
                        continue

                    dtext = getattr(delta, "content", None)
                    if dtext:
                        text_buf.append(dtext)
                        cb(dtext, None)

                    dtcs = getattr(delta, "tool_calls", None) or []
                    for dtc in dtcs:
                        upsert_tool_call(dtc)

                if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                    with self._cancel_lock:
                        self._active_stream_ctx = None
                    return

                final_text = "".join(text_buf)
                tcs = [tool_calls[i] for i in sorted(tool_calls.keys())]
                pseudo = self._finalize_to_envelope(final_text, tcs)
                cb(response=pseudo)
                with self._cancel_lock:
                    self._active_stream_ctx = None
                return
        except openai.BadRequestError as e:
            emsg = str(e)
            lower = emsg.lower()
            if stream and ("param': 'stream" in lower or '"param": "stream"' in lower or "unsupported" in lower or "must be verified" in lower):
                print(_("Unable to query in streaming mode: {error}\nFalling back and retrying!").format(error=emsg))
                _emit_fallback_notice(emsg)
                _fallback_chat_no_stream()
                return
            print(_("General exception encountered while running the query: {error}").format(error=str(e)))
        except Exception as e:
            if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                with self._cancel_lock:
                    self._active_stream_ctx = None
                return
            print(_("General exception encountered while running the query: {error}").format(error=str(e)))

    def query_model_async(self, query, cb, stream=False, additional_model_options=None):
        if isinstance(query, str):
            conversation = [{"role": "user", "content": query}]
        else:
            conversation = list(query)

        t = threading.Thread(target=self._query_via_chat_completions, args=[conversation, cb, stream, additional_model_options])
        t.start()

    def cancel_current_request(self):
        try:
            with self._cancel_lock:
                ev = getattr(self, "_cancel_ev", None)
                ctx = getattr(self, "_active_stream_ctx", None)
                if ev is not None:
                    ev.set()
                if ctx is not None:
                    try:
                        close = getattr(ctx, "close", None)
                        if callable(close):
                            close()
                    except Exception:
                        pass
                self._active_stream_ctx = None
        except Exception:
            pass
