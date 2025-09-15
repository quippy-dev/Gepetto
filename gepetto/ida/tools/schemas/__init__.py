from . import openai_chat_tools
from . import openai_responses_tools
from . import gemini_tools

def get_tools_for_provider(provider_key: str):
    if provider_key == "oai_chat":
        return openai_chat_tools.TOOLS
    elif provider_key == "oai_responses":
        return openai_responses_tools.TOOLS
    elif provider_key == "gemini":
        return gemini_tools.get_tools()
    else:
        # Default to responses tools for now
        return openai_responses_tools.TOOLS

from . import openai_chat_bridge
from . import openai_responses_bridge
from . import gemini_bridge

def add_tool_result(provider_key, messages_or_inputs, tc, result):
    if provider_key == "oai_chat":
        openai_chat_bridge.add_result_to_messages(messages_or_inputs, tc, result)
    elif provider_key == "oai_responses":
        openai_responses_bridge.add_result_to_inputs(messages_or_inputs, tc, result)
    elif provider_key == "gemini":
        gemini_bridge.add_result_to_messages(messages_or_inputs, tc, result)
    else:
        # Default to chat bridge for now
        openai_chat_bridge.add_result_to_messages(messages_or_inputs, tc, result)
