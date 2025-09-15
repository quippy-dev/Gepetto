import json

def _get(obj, key, default=None):
    """Safely get a value from either a dict or an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

def add_result_to_messages(messages, tc, result):
    """
    Appends a tool result to a list of messages for the Gemini API.
    """
    fn = _get(tc, "function", {}) or {}
    tool_name = _get(fn, "name")
    tool_id = _get(tc, "id")

    if isinstance(result, (dict, list)):
        content = json.dumps(result, ensure_ascii=False)
    else:
        content = str(result)

    try:
        parsed = json.loads(content)
    except Exception:
        parsed = content

    if isinstance(parsed, dict) and "content" in parsed:
        response_obj = parsed
    else:
        if isinstance(parsed, (dict, list)):
            txt = json.dumps(parsed, ensure_ascii=False)
        else:
            txt = str(parsed)
        response_obj = {
            "name": tool_name,
            "content": [{"text": txt}],
        }

    messages.append(
        {
            "role": "user",
            "parts": [
                {
                    "function_response": {
                        "name": tool_name,
                        "id": tool_id,
                        "response": response_obj,
                    }
                }
            ],
        }
    )
