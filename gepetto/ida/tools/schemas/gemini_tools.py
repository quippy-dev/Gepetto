# flake8: noqa
from google.genai import types

_ALLOWED_SCHEMA_KEYS = {
    "type",
    "format",
    "description",
    "enum",
    "properties",
    "required",
    "items",
}


def _sanitize_schema(schema):
    if isinstance(schema, dict):
        cleaned = {}
        for k, v in schema.items():
            if k not in _ALLOWED_SCHEMA_KEYS:
                continue
            if k == "properties" and isinstance(v, dict):
                props = {}
                for pk, pv in v.items():
                    sanitized = _sanitize_schema(pv)
                    if sanitized:
                        props[pk] = sanitized
                if props:
                    cleaned["properties"] = props
                continue
            if k == "items":
                sanitized = _sanitize_schema(v)
                if sanitized:
                    cleaned["items"] = sanitized
                continue
            if k == "required" and isinstance(v, list):
                cleaned["required"] = list(v)
                continue
            sanitized = _sanitize_schema(v)
            if sanitized is not None:
                cleaned[k] = sanitized
        if "required" in cleaned:
            if "properties" in cleaned:
                cleaned["required"] = [r for r in cleaned["required"] if r in cleaned["properties"]]
                if not cleaned["required"]:
                    cleaned.pop("required")
            else:
                cleaned.pop("required")
        return cleaned or None
    if isinstance(schema, list):
        sanitized_list = []
        for v in schema:
            sanitized = _sanitize_schema(v)
            if sanitized is not None:
                sanitized_list.append(sanitized)
        return sanitized_list or None
    return schema

def get_tools():
    from .openai_responses_tools import TOOLS as RESPONSES_TOOLS
    function_decls = []
    for t in RESPONSES_TOOLS:
        if t.get("type") != "function":
            continue
        name = t.get("name", "")
        desc = t.get("description")
        params = t.get("parameters")
        if params:
            params = _sanitize_schema(params)
        try:
            function_decls.append(
                types.FunctionDeclaration(
                    name=name,
                    description=desc,
                    parameters=params,
                )
            )
        except Exception:
            # Fallback simple dict; the client may coerce this as needed
            function_decls.append({
                "name": name,
                "description": desc,
                "parameters": params,
            })
    if function_decls:
        return [types.Tool(function_declarations=function_decls)]
    return None
