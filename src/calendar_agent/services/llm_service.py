import json
from typing import Any, cast

from infrastructure.data_models import Message
from infrastructure.openai_gpt_manager import OpenAIChat
from services.mcp_discovery_service import get_tools_and_schemas
from services.renderer_service import render_prompt

_MODEL_NAME = "gpt-5-mini"


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


def _openai_tools_from_mcp(
    tools_list: list[dict[str, Any]], schemas: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]:
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


def _matches_json_type(value: Any, expected: str) -> bool:
    """
    Check whether a Python value matches a basic JSON Schema type.

    Args:
        value: The value to check.
        expected: The JSON Schema type string (e.g., "string", "integer").

    Returns:
        True if the value matches the expected type, else False.
    """
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        is_num = (isinstance(value, int) or isinstance(value, float)) and not isinstance(
            value, bool
        )
        return is_num
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "null":
        return value is None
    # Unknown type: be conservative
    return False


def _validate_args_against_schema(args: dict[str, Any], schema: dict[str, Any]) -> None:
    """
    Validate tool arguments against a simplified subset of JSON Schema.

    This validates required fields and basic property types. It intentionally
    does not implement the full JSON Schema spec to avoid extra dependencies.

    Args:
        args: Parsed arguments returned by the LLM.
        schema: The JSON Schema (from MCP) for the selected tool.

    Raises:
        ValueError: If required fields are missing or any type mismatches occur.
    """
    properties = schema.get("properties")
    required = schema.get("required", [])
    additional_props = schema.get("additionalProperties", True)

    if not isinstance(properties, dict):
        properties = {}
    if not isinstance(required, list):
        required = []

    # Check required fields
    for field in required:
        if field not in args:
            raise ValueError(f"Missing required argument: {field}")

    # Disallow unknown fields if additionalProperties is explicitly false
    if additional_props is False:
        unknown = [k for k in args.keys() if k not in properties]
        if unknown:
            raise ValueError(f"Unknown argument(s) not allowed: {', '.join(unknown)}")

    # Type-check known properties (best-effort)
    for key, val in args.items():
        prop = properties.get(key)
        if not isinstance(prop, dict):
            # No schema for this key; allow unless additionalProperties is False (handled above)
            continue
        expected_type = prop.get("type")
        if expected_type is None:
            continue
        # expected_type may be a string or a list of strings
        if isinstance(expected_type, list):
            if not any(_matches_json_type(val, t) for t in expected_type if isinstance(t, str)):
                msg = f"Argument '{key}' has wrong type; " + f"expected one of {expected_type}"
                raise ValueError(msg)
        elif isinstance(expected_type, str):
            if not _matches_json_type(val, expected_type):
                raise ValueError(f"Argument '{key}' has wrong type; expected {expected_type}")


def _validate_llm_response(
    llm_response: dict[str, Any],
    llm_to_mcp: dict[str, str],
    schemas: dict[str, Any],
) -> dict[str, Any]:
    """
    Validate and normalize the LLM response.

    This ensures there is at most one tool call, the tool name exists in the
    discovered MCP tools, and that the tool arguments conform to the MCP tool's
    JSON Schema.

    Args:
        llm_response: Raw response from the LLM.
        llm_to_mcp: Mapping from OpenAI-safe tool names back to MCP tool names.
        schemas: Full MCP schemas keyed by MCP tool name.

    Returns:
        The normalized LLM response with `tool_name` set to the MCP tool name.

    Raises:
        ValueError: If validation fails.
    """
    # Ensure there is only a single tool call (some models emit tool_calls arrays)
    tool_calls = llm_response.get("tool_calls")
    if isinstance(tool_calls, list) and tool_calls:
        tool_calls_typed: list[Any] = tool_calls
        if len(tool_calls_typed) != 1:
            raise ValueError("Multiple tool calls are not supported.")

    # Validate the tool name returned by the LLM is in the list of available tools
    llm_tool_name = llm_response.get("tool_name", "")
    if llm_tool_name not in llm_to_mcp:
        raise ValueError(f"Unknown tool name returned by LLM: {llm_tool_name}")

    # Convert the LLM tool name back to the MCP name
    mcp_tool_name = llm_to_mcp[llm_tool_name]
    llm_response["tool_name"] = mcp_tool_name

    # Validate the arguments returned by the LLM
    tool_arguments = llm_response.get("tool_arguments", "{}")
    try:
        parsed_any = json.loads(tool_arguments)
        if not isinstance(parsed_any, dict):
            raise ValueError("Arguments are not formed correctly.")
        parsed_args: dict[str, Any] = cast(dict[str, Any], parsed_any)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in tool arguments: {e}") from e

    # Validate arguments against the MCP schema for the selected tool
    tool_schema_any = schemas.get(mcp_tool_name, {}).get("input_schema", {})
    tool_schema: dict[str, Any] = (
        cast(dict[str, Any], tool_schema_any) if isinstance(tool_schema_any, dict) else {}
    )
    _validate_args_against_schema(parsed_args, tool_schema)

    return llm_response


def plan_mcp_call(message: str) -> dict[str, Any]:
    """Plan the MCP call."""
    # Get the available tools and schemas from the MCP
    data = get_tools_and_schemas()
    _manifest = data.get("manifest")  # currently unused
    tools = data.get("tools")
    schemas = data.get("schemas")

    # Validate the tools and schemas
    if not isinstance(tools, list) or not all(isinstance(t, dict) for t in tools or []):
        raise ValueError("Tools are not a list of dictionaries as expected.")
    if not isinstance(schemas, dict):
        raise ValueError("Schemas are not a dictionary as expected.")

    tools_typed: list[dict[str, Any]] = cast(list[dict[str, Any]], tools)
    schemas_typed: dict[str, Any] = cast(dict[str, Any], schemas)

    # Convert the tools and schemas to OpenAI-compatible format
    oai_tools, _, llm_to_mcp = _openai_tools_from_mcp(tools_typed, schemas_typed)

    # Ask the LLM to plan an MCP tools call
    llm = OpenAIChat(model=_MODEL_NAME)
    system_prompt = render_prompt()
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

    # Type assertion: llm.generate() returns a dict-like response and then validate
    assert isinstance(llm_response, dict)
    validated_response = _validate_llm_response(llm_response, llm_to_mcp, schemas_typed)

    return validated_response
