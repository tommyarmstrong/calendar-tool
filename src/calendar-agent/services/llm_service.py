import json
from typing import Any

from infrastructure.data_models import Message
from infrastructure.openai_gpt_manager import OpenAIChat
from services.mcp_discovery_service import get_tools_and_schemas
from services.renderer_service import render_prompt


def _make_name_maps(mcp_tool_names: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    """
    Returns (mcp_to_llm, llm_to_mcp).
    LLM-safe tool names allow only [A-Za-z0-9_-], so we convert '.' -> '_'.
    Handles collisions deterministically by appending __2, __3, ...
    """
    mcp_to_llm: dict[str, str] = {}
    llm_to_mcp: dict[str, str] = {}
    for mcp in mcp_tool_names:
        base = mcp.replace(".", "_")
        candidate = base
        i = 2
        while candidate in llm_to_mcp and llm_to_mcp[candidate] != mcp:
            candidate = f"{base}__{i}"
            i += 1
        mcp_to_llm[mcp] = candidate
        llm_to_mcp[candidate] = mcp
    return mcp_to_llm, llm_to_mcp


def _openai_tools_from_mcp() -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]:
    """
    Builds OpenAI Responses-API tool specs from live MCP discovery.

    The current implementation of GPT 5 seems to require nested tools. They need to be
    flattened to be compatible with the OpenAI API. GPT 5 also rejects tool names that contain dots.
    Tool names need to be converted to use underscores.

    Returns:
      (tools, mcp_to_llm, llm_to_mcp)
        tools      -> list[dict] suitable for `tools=` in client.responses.create(...)
        mcp_to_llm -> map original MCP name -> OpenAI-safe name
        llm_to_mcp -> reverse map (OpenAI-safe -> MCP)

    Example tool item (flattened style, broadly compatible):
      {
        "type": "function",
        "name": "calendar_freebusy",
        "description": "...",
        "parameters": { ... JSON Schema ... }
      }
    """
    data = get_tools_and_schemas()
    tools_list = data["tools"]  # [{name, description, input_schema}, ...]
    schemas = data["schemas"]  # { "<mcp_name>": { "input_schema": {...} }, ... }

    mcp_names = [t["name"] for t in tools_list]
    mcp_to_llm, llm_to_mcp = _make_name_maps(mcp_names)

    oai_tools: list[dict[str, Any]] = []
    for t in tools_list:
        mcp_name = t["name"]
        llm_name = mcp_to_llm[mcp_name]
        params = schemas[mcp_name]["input_schema"]
        oai_tools.append({
            "type": "function",
            "name": llm_name,  # OpenAI-safe
            "description": t.get("description", ""),
            "parameters": params,  # JSON Schema
        })

    return oai_tools, mcp_to_llm, llm_to_mcp


def plan_mcp_call(message: str) -> dict[str, Any]:
    """Plan the MCP call."""

    llm = OpenAIChat(model="gpt-5-mini")

    system_prompt = render_prompt()
    oai_tools, _, llm_to_mcp = _openai_tools_from_mcp()

    llm_response = llm.generate(
        messages=[
            Message(role="system", content=system_prompt),
            Message(role="user", content=message),
        ],
        tools=oai_tools,
        tool_choice="auto",
        verbosity="low",
        reasoning_effort="low",
        max_output_tokens=500,
    )

    # Convert the LLM tool name back to the MCP name
    llm_tool_name = llm_response.get("tool_name", "")
    if llm_tool_name not in llm_to_mcp:
        raise ValueError(f"Unknown tool name returned by LLM: {llm_tool_name}")

    llm_response["tool_name"] = llm_to_mcp[llm_tool_name]

    # validate the response
    tool_name = llm_response.get("tool_name", "")
    tool_arguments = llm_response.get("tool_arguments", "{}")

    if not tool_name or not isinstance(tool_name, str):
        raise ValueError("Tool name was not found.")

    try:
        parsed_args = json.loads(tool_arguments)
        if not isinstance(parsed_args, dict):
            raise ValueError("Arguments are not formed correctly.")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in tool arguments: {e}") from e

    return llm_response
