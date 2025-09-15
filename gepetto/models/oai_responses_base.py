import abc
import threading
from types import SimpleNamespace

import httpx as _httpx
import openai

from gepetto.models.base import LanguageModel
import gepetto.config

_ = gepetto.config._

class OAIResponsesAPI(LanguageModel):
    def __init__(self, model_name):
        self.model_name = model_name
        self.api_model = model_name
        self.client = self._make_client()
        self._cancel_lock = threading.Lock()
        self._cancel_ev: threading.Event | None = None
        self._active_stream_ctx = None
        self._fallback_notice_sent = False
        self.oai_org_unverified = False

    @abc.abstractmethod
    def _make_client(self) -> openai.OpenAI:
        """
        Subclasses must implement this to return a configured OpenAI client.
        """
        pass

    def _build_responses_input(self, conversation):
        system_instructions = []
        input_items = []
        for msg in conversation:
            role = msg.get("role") if isinstance(msg, dict) else getattr(msg, "role", None)
            content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)
            tool_calls = msg.get("tool_calls") if isinstance(msg, dict) else getattr(msg, "tool_calls", None)
            if role == "system":
                if content:
                    system_instructions.append(str(content))
                continue

            if role == "tool":
                call_id = None
                for k in ("tool_call_id", "id"):
                    v = msg.get(k) if isinstance(msg, dict) else getattr(msg, k, None)
                    if v:
                        call_id = str(v)
                        break
                out = content
                if isinstance(out, (dict, list)):
                    try:
                        import json as _json
                        out = _json.dumps(out, ensure_ascii=False)
                    except Exception:
                        out = str(out)
                elif out is None:
                    out = ""
                input_items.append({
                    "type": "function_call_output",
                    "call_id": call_id or "",
                    "output": str(out),
                })
                continue

            item = {"role": role or "user"}
            parts = []
            part_type = "output_text" if (role == "assistant") else "input_text"
            if isinstance(content, list):
                for p in content:
                    if isinstance(p, dict) and ("text" in p):
                        txt = p.get("text", "")
                        parts.append({"type": part_type, "text": txt})
                    elif isinstance(p, dict) and p.get("type") in ("input_text", "output_text"):
                        parts.append({"type": p.get("type"), "text": p.get("text", "")})
                    else:
                        parts.append({"type": part_type, "text": str(p)})
            elif isinstance(content, str):
                parts.append({"type": part_type, "text": content})
            elif content is None:
                pass
            else:
                parts.append({"type": part_type, "text": str(content)})

            if role == "assistant" and tool_calls:
                try:
                    for tc in tool_calls:
                        if isinstance(tc, dict):
                            tc_id = tc.get("id") or ""
                            fn = tc.get("function") or {}
                            name = fn.get("name") or ""
                            args = fn.get("arguments") or ""
                        else:
                            tc_id = getattr(tc, "id", "")
                            fn = getattr(tc, "function", None)
                            name = getattr(fn, "name", "") if fn is not None else ""
                            args = getattr(fn, "arguments", "") if fn is not None else ""
                        input_items.append({
                            "type": "function_call",
                            "call_id": str(tc_id or ""),
                            "name": str(name or ""),
                            "arguments": str(args or ""),
                        })
                except Exception:
                    pass

            if parts:
                item["content"] = parts
            input_items.append(item)

        instructions = "\n".join(system_instructions) if system_instructions else None
        return instructions, input_items

    def _build_responses_request_args(self, instructions, input_items, opts):
        return {
            "model": self.api_model,
            "input": input_items if len(input_items) > 0 else None,
            "instructions": instructions,
            **opts,
        }

    def _finalize_to_envelope(self, output, tool_calls, summaries):
        # This is a placeholder. The actual implementation will depend on the ResultEnvelope structure.
        return SimpleNamespace(output=output, tool_calls=tool_calls, summaries=summaries)

    def _query_via_responses(self, conversation, cb, stream, additional_model_options):
        instructions, input_items = self._build_responses_input(conversation)
        opts = dict(additional_model_options or {})

        text_opts = {}
        rf = opts.pop("response_format", None)
        if isinstance(rf, dict):
            if rf.get("type") == "json_object":
                text_opts["format"] = "json"
            elif rf.get("type") == "json_schema":
                js = rf.get("json_schema", {})
                name = js.get("name") or "Output"
                text_opts["format"] = {
                    "type": "json_schema",
                    "name": name,
                    "json_schema": {
                        "strict": True,
                        "schema": js.get("schema", {"type": "object"}),
                    },
                }
        if text_opts:
            opts["text"] = text_opts

        if "max_tokens" in opts and "max_output_tokens" not in opts:
            try:
                opts["max_output_tokens"] = int(opts.pop("max_tokens"))
            except Exception:
                opts.pop("max_tokens", None)

        opts["store"] = False

        if "parallel_tool_calls" not in opts:
            try:
                ptc = gepetto.config.get_config("OpenAI", "PARALLEL_TOOL_CALLS", default="false")
                ptc_bool = str(ptc).strip().lower() in ("1", "true", "yes", "on")
            except Exception:
                ptc_bool = False
            opts["parallel_tool_calls"] = ptc_bool

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

        def _fallback_responses_no_stream():
            local_opts = dict(opts)
            local_opts.pop("reasoning", None)
            try:
                request_args = self._build_responses_request_args(instructions, input_items, local_opts)
                resp = self.client.responses.create(**request_args)
            except Exception as _e:
                print(_("Exception encountered while retrying without streaming: {error}").format(error=str(_e)))
                return

            try:
                agg = getattr(resp, "output_text", None)
                if isinstance(agg, str) and agg:
                    cb(agg, None)
                else:
                    text_chunks = []
                    outputs = getattr(resp, "output", None) or []
                    for item in outputs:
                        itype = getattr(item, "type", None) or (item.get("type") if isinstance(item, dict) else None)
                        if itype != "output_text":
                            continue
                        parts = getattr(item, "content", None) or (item.get("content") if isinstance(item, dict) else None)
                        if isinstance(parts, list):
                            for p in parts:
                                txt = getattr(p, "text", None) or (p.get("text") if isinstance(p, dict) else None)
                                if isinstance(txt, str) and txt:
                                    text_chunks.append(txt)
                    if text_chunks:
                        cb("".join(text_chunks), None)
            except Exception:
                pass

            try:
                cb(response=resp)
            except Exception:
                pass

        if stream and self.oai_org_unverified:
            opts.pop("reasoning", None)
            if not self._fallback_notice_sent:
                _emit_fallback_notice(_("Previously detected org/model streaming restriction"))
                self._fallback_notice_sent = True
            _fallback_responses_no_stream()
            return

        try:
            request_args = self._build_responses_request_args(instructions, input_items, opts)
            if not stream:
                resp = self.client.responses.create(**request_args)
                cb(response=resp)
                return
            else:
                with self.client.responses.stream(**request_args) as stream_ctx:
                    with self._cancel_lock:
                        self._cancel_ev = getattr(self, "_cancel_ev", None) or threading.Event()
                        self._active_stream_ctx = stream_ctx

                    sent_thinking = False
                    saw_reasoning = False
                    summary_done = False
                    buffered_output: list[str] = []
                    for event in stream_ctx:
                        if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                            try:
                                stream_ctx.close()
                            except Exception:
                                pass
                            with self._cancel_lock:
                                self._active_stream_ctx = None
                            break

                        etype = getattr(event, "type", None)
                        if (not sent_thinking) and isinstance(etype, str) and etype.startswith("response.reasoning"):
                            try:
                                cb({"status": "thinking"}, None)
                            except Exception:
                                pass
                            sent_thinking = True
                            saw_reasoning = True

                        if etype == "response.reasoning_text.delta" or (isinstance(etype, str) and etype.startswith("response.reasoning") and etype.endswith(".delta") and ("summary" not in etype)):
                            delta = getattr(event, "delta", None)
                            if isinstance(delta, str) and delta:
                                cb({"reasoning_text_delta": delta}, None)
                            continue
                        if etype == "response.reasoning_text.done" or (isinstance(etype, str) and etype.startswith("response.reasoning") and etype.endswith(".done") and ("summary" not in etype)):
                            text = getattr(event, "text", None)
                            if isinstance(text, str):
                                cb({"reasoning_text_done": text}, None)
                            continue

                        if isinstance(etype, str) and "reasoning_summary" in etype:
                            if etype.endswith("summary_part.delta") or etype.endswith("reasoning_summary_part.delta"):
                                piece = getattr(event, "delta", None) or getattr(event, "text", None)
                                if isinstance(piece, str) and piece:
                                    cb({"reasoning_summary_part_delta": piece}, None)
                                continue
                            if etype.endswith("summary_part.added") or etype.endswith("reasoning_summary_part.added"):
                                piece = getattr(event, "text", None) or getattr(event, "delta", None)
                                if isinstance(piece, str) and piece:
                                    cb({"reasoning_summary_part_delta": piece + "\n"}, None)
                                continue
                            if etype.endswith("reasoning_summary_text.delta") or etype.endswith("summary_text.delta"):
                                piece = getattr(event, "delta", None) or getattr(event, "text", None)
                                if isinstance(piece, str) and piece:
                                    cb({"reasoning_summary_text_delta": piece}, None)
                                continue
                            if etype.endswith("reasoning_summary_text.done") or etype.endswith("summary_text.done") or etype.endswith("summary.done"):
                                text = getattr(event, "text", None)
                                if isinstance(text, str) and text:
                                    cb({"reasoning_summary_done": text}, None)
                                summary_done = True
                                if buffered_output:
                                    try:
                                        cb("".join(buffered_output), None)
                                    except Exception:
                                        pass
                                    buffered_output.clear()
                                continue

                        if etype == "response.output_text.delta":
                            delta = getattr(event, "delta", None)
                            if isinstance(delta, str) and delta:
                                if saw_reasoning and not summary_done:
                                    buffered_output.append(delta)
                                else:
                                    cb(delta, None)
                        elif etype == "response.output_text.done":
                            if buffered_output and not summary_done:
                                try:
                                    cb("".join(buffered_output), None)
                                except Exception:
                                    pass
                                buffered_output.clear()
                        else:
                            pass

                    if buffered_output:
                        try:
                            cb("".join(buffered_output), None)
                        except Exception:
                            pass
                        buffered_output.clear()

                    if getattr(self, "_cancel_ev", None) is not None and self._cancel_ev.is_set():
                        with self._cancel_lock:
                            self._active_stream_ctx = None
                        return

                    final = stream_ctx.get_final_response()
                    cb(response=final)
                    with self._cancel_lock:
                        self._active_stream_ctx = None
                    return
        except openai.BadRequestError as e:
            emsg = str(e)
            lower = emsg.lower()
            if stream and ("param': 'stream" in lower or '"param": "stream"' in lower or "unsupported" in lower or "verify organization" in lower or "must be verified" in lower or "organization is not verified" in lower):
                print(_("Unable to query in streaming mode: {error}\nFalling back and retrying!").format(error=emsg))
                self.oai_org_unverified = True
                opts.pop("reasoning", None)
                _emit_fallback_notice(emsg)
                _fallback_responses_no_stream()
                return
            if ("reasoning" in lower) or ("reasoning.summary" in lower):
                try:
                    print(_("Reasoning not permitted for this org/model; retrying without reasoning."))
                except Exception:
                    pass
                opts.pop("reasoning", None)
                try:
                    cb({"status": "notice", "text": _("Reasoning summaries are disabled for this org/model; continuing without reasoning.")}, None)
                except Exception:
                    pass
                _fallback_responses_no_stream()
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

        t = threading.Thread(target=self._query_via_responses, args=[conversation, cb, stream, additional_model_options])
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
