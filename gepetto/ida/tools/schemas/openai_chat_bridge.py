import json

def _get(obj, key, default=None):
    """Safely get a value from either a dict or an object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

def add_result_to_messages(messages, tc, result):
    """
    Appends a tool result to a list of messages for the OpenAI Chat Completions API.
    """
    tc_id = _get(tc, "id")
    fn = _get(tc, "function", {}) or {}
    fn_name = _get(fn, "name")

    # Ensure the result is a JSON string if it's a dict or list
    if isinstance(result, (dict, list)):
        content = json.dumps(result, ensure_ascii=False)
    else:
        content = str(result)

    messages.append(
        {
            "role": "tool",
            "tool_call_id": tc_id,
            "name": fn_name,
            "content": content,
        }
    )
