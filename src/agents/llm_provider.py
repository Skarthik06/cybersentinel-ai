"""
CyberSentinel AI — LLM Provider Abstraction Layer
==================================================
Supports three LLM providers switchable via a single environment variable:

    LLM_PROVIDER=claude    → Anthropic Claude (default)
    LLM_PROVIDER=openai    → OpenAI GPT-4o
    LLM_PROVIDER=gemini    → Google Gemini

All providers expose the same interface so the rest of the codebase
doesn't need to know which provider is running.

Tool / function calling:
  - Claude  : native tool_use via Anthropic Messages API
  - OpenAI  : native function_calling via OpenAI Chat Completions API
  - Gemini  : native function_declarations via Google Generative AI SDK

Usage:
    from src.agents.llm_provider import get_provider
    provider = get_provider()
    response = await provider.chat(messages, tools=MCP_TOOLS)
    if response.has_tool_calls:
        for call in response.tool_calls:
            result = await execute(call.name, call.arguments)
        await provider.submit_tool_results(messages, response, results)
    else:
        text = response.text
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.core.logger import get_logger

logger = get_logger("llm-provider")

# ── Provider selection ────────────────────────────────────────────────────────
LLM_PROVIDER   = os.getenv("LLM_PROVIDER", "claude").lower().strip()

# API keys
ANTHROPIC_KEY  = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_KEY     = os.getenv("OPENAI_API_KEY", "")
GEMINI_KEY     = os.getenv("GOOGLE_API_KEY", "")

# Model overrides — set in .env to avoid hardcoding model names in code
LLM_MODEL_PRIMARY   = os.getenv("LLM_MODEL_PRIMARY",   "")
LLM_MODEL_FAST      = os.getenv("LLM_MODEL_FAST",      "")
LLM_MODEL_ANALYSIS  = os.getenv("LLM_MODEL_ANALYSIS",  "")

# Inference temperature — set in .env (0.0 = deterministic, 1.0 = creative)
LLM_TEMPERATURE     = float(os.getenv("LLM_TEMPERATURE", "0.2"))


# ── Unified response dataclass ────────────────────────────────────────────────
@dataclass
class ToolCall:
    """A single tool invocation from the LLM."""
    id:        str
    name:      str
    arguments: Dict[str, Any]


@dataclass
class LLMResponse:
    """
    Unified response object returned by all providers.
    Callers only interact with this — no provider-specific objects leak out.
    """
    text:          str = ""
    has_tool_calls: bool = False
    tool_calls:    List[ToolCall] = field(default_factory=list)
    stop_reason:   str = "end_turn"      # "end_turn" | "tool_use" | "stop"
    raw:           Any = None            # original provider response (for debugging)


# ── Base provider interface ────────────────────────────────────────────────────
class LLMProvider(ABC):
    """
    Abstract base class that all providers implement.
    Callers use only this interface — never provider-specific SDKs.
    """

    @abstractmethod
    async def chat(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        system: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """
        Send a chat request and return a unified LLMResponse.

        Args:
            messages  : conversation history [{role, content}, ...]
            tools     : MCP tool definitions (provider-agnostic format)
            system    : system prompt string
            model     : override the default model for this call
            max_tokens: maximum response tokens
        """

    @abstractmethod
    async def submit_tool_results(
        self,
        messages: List[Dict],
        prev_response: LLMResponse,
        tool_results: List[Dict],  # [{tool_call_id, name, content}, ...]
        tools: Optional[List[Dict]] = None,
        system: Optional[str] = None,
    ) -> LLMResponse:
        """
        Submit tool execution results back to the LLM and get its next response.
        Handles provider-specific message format differences.
        """

    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name for logging."""


# ── Claude Provider ────────────────────────────────────────────────────────────
class ClaudeProvider(LLMProvider):
    """
    Anthropic Claude via the official anthropic Python SDK.
    Supports native tool_use with structured ToolUseBlock responses.

    Default models:
      primary  : claude-opus-4-5   (best reasoning, for investigation)
      fast     : claude-haiku-4-5-20251001  (fast, for CVE analysis)
      analysis : claude-sonnet-4-6  (balanced, for daily reports)
    """

    DEFAULTS = {
        "primary":  "claude-opus-4-5",
        "fast":     "claude-haiku-4-5-20251001",
        "analysis": "claude-sonnet-4-6",
    }

    def __init__(self):
        try:
            import anthropic
            self._client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_KEY)
            logger.info(f"✅ Claude provider initialised")
        except ImportError:
            raise RuntimeError("anthropic package not installed. Run: pip install anthropic")

    def name(self) -> str:
        return "Claude (Anthropic)"

    def _resolve_model(self, model: Optional[str], tier: str = "primary") -> str:
        if model:
            return model
        env_override = LLM_MODEL_PRIMARY if tier == "primary" else \
                       LLM_MODEL_FAST if tier == "fast" else LLM_MODEL_ANALYSIS
        return env_override or self.DEFAULTS[tier]

    async def chat(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        system: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        kwargs: Dict[str, Any] = {
            "model":      self._resolve_model(model),
            "max_tokens": max_tokens,
            "messages":   messages,
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools  # Claude accepts MCP format directly

        response = await self._client.messages.create(**kwargs)

        tool_calls = []
        text = ""
        for block in response.content:
            if hasattr(block, "text"):
                text = block.text
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.id,
                    name=block.name,
                    arguments=block.input,
                ))

        return LLMResponse(
            text=text,
            has_tool_calls=len(tool_calls) > 0,
            tool_calls=tool_calls,
            stop_reason=response.stop_reason or "end_turn",
            raw=response,
        )

    async def submit_tool_results(
        self,
        messages: List[Dict],
        prev_response: LLMResponse,
        tool_results: List[Dict],
        tools: Optional[List[Dict]] = None,
        system: Optional[str] = None,
    ) -> LLMResponse:
        # Append assistant message with tool_use blocks
        messages.append({"role": "assistant", "content": prev_response.raw.content})
        # Append tool results in Claude format
        messages.append({
            "role": "user",
            "content": [
                {
                    "type":        "tool_result",
                    "tool_use_id": r["tool_call_id"],
                    "content":     str(r["content"]),
                }
                for r in tool_results
            ],
        })
        return await self.chat(messages, tools=tools, system=system)


# ── OpenAI GPT Provider ────────────────────────────────────────────────────────
class OpenAIProvider(LLMProvider):
    """
    OpenAI GPT-4o-mini via the official openai Python SDK.
    Converts MCP tool format to OpenAI function_calling format.

    Default models:
      primary  : gpt-4o-mini     (cost-efficient, sufficient for investigation)
      fast     : gpt-4o-mini     (fast, for CVE analysis)
      analysis : gpt-4o-mini     (balanced, for daily reports)
    """

    DEFAULTS = {
        "primary":  "gpt-4o-mini",
        "fast":     "gpt-4o-mini",
        "analysis": "gpt-4o-mini",
    }

    def __init__(self):
        try:
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(api_key=OPENAI_KEY)
            logger.info("✅ OpenAI GPT provider initialised")
        except ImportError:
            raise RuntimeError("openai package not installed. Run: pip install openai")

    def name(self) -> str:
        return "GPT-4o (OpenAI)"

    def _resolve_model(self, model: Optional[str], tier: str = "primary") -> str:
        if model:
            return model
        env_override = LLM_MODEL_PRIMARY if tier == "primary" else \
                       LLM_MODEL_FAST if tier == "fast" else LLM_MODEL_ANALYSIS
        return env_override or self.DEFAULTS[tier]

    def _convert_tools(self, tools: List[Dict]) -> List[Dict]:
        """
        Convert MCP tool format (Anthropic-style) → OpenAI function format.

        MCP format:
          {name, description, input_schema: {type, properties, required}}

        OpenAI format:
          {type: "function", function: {name, description, parameters: {type, properties, required}}}
        """
        converted = []
        for t in tools:
            converted.append({
                "type": "function",
                "function": {
                    "name":        t["name"],
                    "description": t.get("description", ""),
                    "parameters":  t.get("input_schema", {"type": "object", "properties": {}}),
                },
            })
        return converted

    async def chat(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        system: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        oai_messages = []

        # Prepend system message if provided
        if system:
            oai_messages.append({"role": "system", "content": system})

        # Pass all messages through as-is — they are already in OpenAI format.
        # Do NOT reconstruct: tool messages need tool_call_id preserved,
        # assistant messages with tool_calls have content=None.
        oai_messages.extend(messages)

        kwargs: Dict[str, Any] = {
            "model":       self._resolve_model(model),
            "max_tokens":  max_tokens,
            "messages":    oai_messages,
            "temperature": LLM_TEMPERATURE,
        }
        if tools:
            kwargs["tools"]        = self._convert_tools(tools)
            kwargs["tool_choice"]  = "auto"

        response = await self._client.chat.completions.create(**kwargs)
        message = response.choices[0].message

        tool_calls = []
        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=args,
                ))

        stop = response.choices[0].finish_reason or "stop"
        return LLMResponse(
            text=message.content or "",
            has_tool_calls=len(tool_calls) > 0,
            tool_calls=tool_calls,
            stop_reason="tool_use" if tool_calls else stop,
            raw=response,
        )

    async def submit_tool_results(
        self,
        messages: List[Dict],
        prev_response: LLMResponse,
        tool_results: List[Dict],
        tools: Optional[List[Dict]] = None,
        system: Optional[str] = None,
        max_tokens: int = 512,
    ) -> LLMResponse:
        raw_msg = prev_response.raw.choices[0].message

        # Append assistant message with tool_calls
        messages.append({
            "role":       "assistant",
            "content":    raw_msg.content,
            "tool_calls": [
                {
                    "id":       tc.id,
                    "type":     "function",
                    "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                }
                for tc in prev_response.tool_calls
            ],
        })

        # Append one tool message per result
        for r in tool_results:
            messages.append({
                "role":         "tool",
                "tool_call_id": r["tool_call_id"],
                "content":      str(r["content"]),
            })

        return await self.chat(messages, tools=tools, system=system, max_tokens=max_tokens)


# ── Gemini Provider ────────────────────────────────────────────────────────────
class GeminiProvider(LLMProvider):
    """
    Google Gemini via the google-generativeai Python SDK.
    Converts MCP tool format to Gemini function_declarations format.

    Default models:
      primary  : gemini-1.5-pro     (best reasoning, for investigation)
      fast     : gemini-1.5-flash   (fast, for CVE analysis)
      analysis : gemini-1.5-pro     (balanced, for daily reports)
    """

    DEFAULTS = {
        "primary":  "gemini-2.5-flash",
        "fast":     "gemini-2.5-flash",
        "analysis": "gemini-2.5-flash",
    }

    def __init__(self):
        try:
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_KEY)
            self._genai = genai
            logger.info("✅ Gemini provider initialised")
        except ImportError:
            raise RuntimeError(
                "google-generativeai package not installed. "
                "Run: pip install google-generativeai"
            )

    def name(self) -> str:
        return "Gemini (Google)"

    def _resolve_model(self, model: Optional[str], tier: str = "primary") -> str:
        if model:
            return model
        env_override = LLM_MODEL_PRIMARY if tier == "primary" else \
                       LLM_MODEL_FAST if tier == "fast" else LLM_MODEL_ANALYSIS
        return env_override or self.DEFAULTS[tier]

    def _convert_tools(self, tools: List[Dict]):
        """
        Convert MCP tool format → Gemini function_declarations format.

        MCP format:
          {name, description, input_schema: {type, properties, required}}

        Gemini format:
          FunctionDeclaration(name, description, parameters as plain dict)

        Note: google-generativeai 0.7.0 calls .copy() on the parameters dict
        internally, so parameters must be a plain dict (not protos.Schema).
        """
        from google.generativeai.types import FunctionDeclaration

        declarations = []
        for t in tools:
            schema = t.get("input_schema", {})
            props  = schema.get("properties", {})

            # Build parameters as a plain OpenAPI-style dict — the SDK converts it
            def _prop(v):
                p = {"type": v.get("type", "string"), "description": v.get("description", "")}
                if v.get("type") == "array":
                    p["items"] = {"type": v.get("items", {}).get("type", "string")}
                return p

            parameters = {
                "type": "object",
                "properties": {k: _prop(v) for k, v in props.items()},
            }
            if schema.get("required"):
                parameters["required"] = schema["required"]

            declarations.append(FunctionDeclaration(
                name=t["name"],
                description=t.get("description", ""),
                parameters=parameters,
            ))

        return [self._genai.types.Tool(function_declarations=declarations)]

    def _build_history(
        self, messages: List[Dict], system: Optional[str]
    ) -> tuple:
        """
        Gemini uses a different message structure:
          - system_instruction is separate from history
          - roles: "user" | "model" (not "assistant")
          - content is a list of Parts
        """
        history = []
        last_user = None

        for msg in messages:
            role    = "user" if msg["role"] == "user" else "model"
            content = msg.get("content", "")

            if isinstance(content, str):
                parts = [{"text": content}]
            elif isinstance(content, list):
                # Handle tool_result content — flatten to text
                parts = [{"text": json.dumps(c) if isinstance(c, dict) else str(c)}
                         for c in content]
            else:
                parts = [{"text": str(content)}]

            history.append({"role": role, "parts": parts})

        # Last message must be from user — extract it as the prompt
        if history and history[-1]["role"] == "user":
            last_user = history.pop()

        return history, last_user, system

    async def chat(
        self,
        messages: List[Dict],
        tools: Optional[List[Dict]] = None,
        system: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        model_name = self._resolve_model(model)
        history, last_user_msg, sys_instruction = self._build_history(messages, system)

        model_obj = self._genai.GenerativeModel(
            model_name=model_name,
            system_instruction=sys_instruction,
            tools=self._convert_tools(tools) if tools else None,
        )

        chat_session = model_obj.start_chat(history=history)
        user_text = last_user_msg["parts"][0]["text"] if last_user_msg else ""

        response = await chat_session.send_message_async(
            user_text,
            generation_config=self._genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
            ),
        )

        tool_calls = []
        text = ""

        for part in response.parts:
            if part.text:
                text += part.text
            elif part.function_call:
                fc = part.function_call
                # Generate a stable ID from name + args hash
                call_id = f"call_{fc.name}_{abs(hash(str(dict(fc.args))))}"
                tool_calls.append(ToolCall(
                    id=call_id,
                    name=fc.name,
                    arguments=dict(fc.args),
                ))

        has_tools = len(tool_calls) > 0
        return LLMResponse(
            text=text,
            has_tool_calls=has_tools,
            tool_calls=tool_calls,
            stop_reason="tool_use" if has_tools else "end_turn",
            raw=response,
        )

    async def submit_tool_results(
        self,
        messages: List[Dict],
        prev_response: LLMResponse,
        tool_results: List[Dict],
    ) -> LLMResponse:
        """
        Reconstruct the full conversation history including:
          1. All user messages up to and including the last one
          2. The model's function_call turn (from prev_response.raw)
        Then send function_response parts as the next turn.

        Gemini requires: user → model_function_call → function_response
        The previous implementation dropped the model turn, causing the 400 error.
        """
        model_name = self._resolve_model(None)

        # Build history including the last user message
        history, last_user_msg, sys_instruction = self._build_history(messages, None)
        if last_user_msg:
            history.append(last_user_msg)

        # Append the model's function_call turn from the previous response
        # prev_response.raw.candidates[0].content is a Content(role="model", parts=[FunctionCall...])
        try:
            model_content = prev_response.raw.candidates[0].content
            history.append(model_content)
        except (IndexError, AttributeError):
            # Fallback: manually reconstruct from tool_calls
            model_parts = [
                self._genai.protos.Part(
                    function_call=self._genai.protos.FunctionCall(
                        name=tc.name,
                        args=tc.arguments,
                    )
                )
                for tc in prev_response.tool_calls
            ]
            history.append({"role": "model", "parts": model_parts})

        model_obj = self._genai.GenerativeModel(
            model_name=model_name,
            system_instruction=sys_instruction,
        )
        chat_session = model_obj.start_chat(history=history)

        # Build function_response parts for each result
        fn_responses = []
        for r in tool_results:
            fn_responses.append(
                self._genai.protos.Part(
                    function_response=self._genai.protos.FunctionResponse(
                        name=r["name"],
                        response={"result": str(r["content"])},
                    )
                )
            )

        response = await chat_session.send_message_async(fn_responses)

        # Extract text and any follow-on tool calls
        text = ""
        tool_calls = []
        for part in response.parts:
            if hasattr(part, "text") and part.text:
                text += part.text
            elif hasattr(part, "function_call") and part.function_call.name:
                fc = part.function_call
                call_id = f"call_{fc.name}_{abs(hash(str(dict(fc.args))))}"
                tool_calls.append(ToolCall(
                    id=call_id,
                    name=fc.name,
                    arguments=dict(fc.args),
                ))

        has_tools = len(tool_calls) > 0
        return LLMResponse(
            text=text,
            has_tool_calls=has_tools,
            tool_calls=tool_calls,
            stop_reason="tool_use" if has_tools else "end_turn",
            raw=response,
        )


# ── Factory ────────────────────────────────────────────────────────────────────
_provider_instance: Optional[LLMProvider] = None


def get_provider() -> LLMProvider:
    """
    Return the singleton LLM provider based on LLM_PROVIDER env var.

    LLM_PROVIDER=claude  → ClaudeProvider  (requires ANTHROPIC_API_KEY)
    LLM_PROVIDER=openai  → OpenAIProvider  (requires OPENAI_API_KEY)
    LLM_PROVIDER=gemini  → GeminiProvider  (requires GOOGLE_API_KEY)
    """
    global _provider_instance
    if _provider_instance is not None:
        return _provider_instance

    provider_map = {
        "claude":    ClaudeProvider,
        "anthropic": ClaudeProvider,    # alias
        "openai":    OpenAIProvider,
        "gpt":       OpenAIProvider,    # alias
        "gpt4":      OpenAIProvider,    # alias
        "gemini":    GeminiProvider,
        "google":    GeminiProvider,    # alias
    }

    cls = provider_map.get(LLM_PROVIDER)
    if cls is None:
        raise ValueError(
            f"Unknown LLM_PROVIDER='{LLM_PROVIDER}'. "
            f"Valid options: claude, openai, gemini"
        )

    # Validate API key presence
    key_map = {
        ClaudeProvider:  ("ANTHROPIC_API_KEY", ANTHROPIC_KEY),
        OpenAIProvider:  ("OPENAI_API_KEY",    OPENAI_KEY),
        GeminiProvider:  ("GOOGLE_API_KEY",    GEMINI_KEY),
    }
    env_var, key_value = key_map[cls]
    if not key_value:
        raise RuntimeError(
            f"LLM_PROVIDER={LLM_PROVIDER} requires {env_var} to be set in .env"
        )

    _provider_instance = cls()
    logger.info(f"🤖 LLM Provider: {_provider_instance.name()} (LLM_PROVIDER={LLM_PROVIDER})")
    return _provider_instance


def available_providers() -> Dict[str, bool]:
    """
    Returns which providers are available based on configured API keys.
    Used by the health endpoint and the frontend status indicator.
    """
    return {
        "claude": bool(ANTHROPIC_KEY),
        "openai": bool(OPENAI_KEY),
        "gemini": bool(GEMINI_KEY),
        "active": LLM_PROVIDER,
    }
