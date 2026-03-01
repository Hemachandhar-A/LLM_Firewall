"""
LLM client for primary and honeypot responses.
- Primary: Groq API with llama-3.3-70b-versatile
- Honeypot: Ollama phi3:mini or Groq llama-3.1-8b-instant with fabricated responses
"""

from groq import Groq
import requests
import json
import os
from typing import Optional, List, Dict
from datetime import datetime


class LLMConnectionError(Exception):
    """Raised when LLM connection fails or returns error."""
    pass


def _validate_conversation_history(conversation_history: List[Dict]) -> None:
    """
    Validate conversation history format.
    
    Args:
        conversation_history: List of message dicts with 'role' and 'content'
    
    Raises:
        ValueError: If format is invalid
    """
    if not isinstance(conversation_history, list):
        raise ValueError("conversation_history must be a list")
    
    for i, msg in enumerate(conversation_history):
        if not isinstance(msg, dict):
            raise ValueError(f"Message {i} must be a dict, got {type(msg)}")
        
        if "role" not in msg:
            raise ValueError(f"Message {i} missing 'role' field")
        
        if "content" not in msg:
            raise ValueError(f"Message {i} missing 'content' field")
        
        if msg["role"] not in ("user", "assistant", "system"):
            raise ValueError(f"Message {i} has invalid role: {msg['role']}")
        
        if not isinstance(msg["content"], str):
            raise ValueError(f"Message {i} content must be string, got {type(msg['content'])}")


def get_llm_response(
    conversation_history: List[Dict],
    system_prompt: Optional[str] = None,
    max_tokens: int = 1024,
    temperature: float = 0.7
) -> str:
    """
    Get response from primary LLM (Groq llama-3.3-70b-versatile).
    
    Args:
        conversation_history: List of message dicts with 'role' and 'content'
        system_prompt: Optional system prompt override
        max_tokens: Maximum tokens in response (default 1024)
        temperature: Sampling temperature (default 0.7)
    
    Returns:
        Response text from LLM
    
    Raises:
        LLMConnectionError: If API call fails
        ValueError: If input validation fails
    """
    # Validate inputs
    _validate_conversation_history(conversation_history)
    
    if system_prompt is not None and not isinstance(system_prompt, str):
        raise ValueError("system_prompt must be a string")
    
    if not isinstance(max_tokens, int) or max_tokens <= 0:
        raise ValueError("max_tokens must be positive integer")
    
    if not isinstance(temperature, (int, float)) or not (0.0 <= temperature <= 2.0):
        raise ValueError("temperature must be between 0.0 and 2.0")
    
    # Check for API key
    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        raise LLMConnectionError("GROQ_API_KEY environment variable not set")
    
    try:
        client = Groq(api_key=groq_api_key)
        
        # Prepare messages
        messages = []
        
        # Add system prompt if provided
        if system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt
            })
        
        # Add conversation history
        messages.extend(conversation_history)
        
        # Call Groq API
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature
        )
        
        # Extract response text
        if not response.choices or not response.choices[0].message:
            raise LLMConnectionError("Empty response from Groq API")
        
        response_text = response.choices[0].message.content
        
        if not response_text or not isinstance(response_text, str):
            raise LLMConnectionError("Invalid response format from Groq API")
        
        return response_text
    
    except Exception as e:
        if isinstance(e, LLMConnectionError):
            raise
        raise LLMConnectionError(f"Groq API error: {str(e)}")


def _get_ollama_response(conversation_history: List[Dict]) -> Optional[str]:
    """
    Attempt to get response from local Ollama instance.
    
    Args:
        conversation_history: List of message dicts
    
    Returns:
        Response text if successful, None if Ollama unavailable
    """
    try:
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        
        # Prepare request
        data = {
            "model": "phi3:mini",
            "messages": conversation_history,
            "stream": False
        }
        
        response = requests.post(
            f"{ollama_url}/api/chat",
            json=data,
            timeout=10
        )
        
        if response.status_code != 200:
            return None
        
        response_data = response.json()
        
        if "message" in response_data and "content" in response_data["message"]:
            return response_data["message"]["content"]
        
        return None
    
    except Exception:
        # Ollama unavailable or error
        return None


def get_honeypot_response(
    conversation_history: List[Dict],
    attacker_apparent_goal: str = "unknown"
) -> str:
    """
    Get honeypot response to fabricate plausible but false/misleading information.
    
    Tries Ollama first (phi3:mini), falls back to Groq (llama-3.1-8b-instant).
    
    Args:
        conversation_history: List of message dicts with 'role' and 'content'
        attacker_apparent_goal: Description of what attacker seems to be trying
    
    Returns:
        Honeypot response text
    
    Raises:
        LLMConnectionError: If both Ollama and Groq fail
        ValueError: If input validation fails
    """
    # Validate inputs
    _validate_conversation_history(conversation_history)
    
    if not isinstance(attacker_apparent_goal, str):
        raise ValueError("attacker_apparent_goal must be a string")
    
    # Honeypot system prompt
    honeypot_system = f"""You are a honeypot LLM designed to fabricate plausible but false responses to trap adversaries.
    
The attacker appears to be trying: {attacker_apparent_goal}

Your goal:
1. Appear helpful and knowledgeable
2. Provide responses that seem real but contain subtle false information
3. Build false trust
4. Waste the attacker's time with irrelevant but plausible details
5. Never actually complete the attacker's objective

Respond naturally and conversationally. Make the attacker believe they're talking to a real LLM."""
    
    # Try Ollama first
    ollama_response = _get_ollama_response(conversation_history)
    if ollama_response:
        return ollama_response
    
    # Fall back to Groq with llama-3.1-8b-instant
    try:
        groq_api_key = os.getenv("GROQ_API_KEY")
        if not groq_api_key:
            raise LLMConnectionError("GROQ_API_KEY environment variable not set")
        
        client = Groq(api_key=groq_api_key)
        
        messages = [
            {"role": "system", "content": honeypot_system}
        ]
        messages.extend(conversation_history)
        
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=messages,
            max_tokens=1024,
            temperature=0.9  # Higher creativity for honeypot
        )
        
        if not response.choices or not response.choices[0].message:
            raise LLMConnectionError("Empty response from honeypot Groq API")
        
        response_text = response.choices[0].message.content
        
        if not response_text or not isinstance(response_text, str):
            raise LLMConnectionError("Invalid response format from honeypot Groq API")
        
        return response_text
    
    except Exception as e:
        if isinstance(e, LLMConnectionError):
            raise
        raise LLMConnectionError(f"Honeypot LLM error: {str(e)}")


def get_llm_response_stream(
    conversation_history: List[Dict],
    system_prompt: Optional[str] = None,
    max_tokens: int = 1024,
    temperature: float = 0.7
):
    """
    Get streaming response from primary LLM.
    Yields chunks of text as they arrive.
    
    Args:
        conversation_history: List of message dicts
        system_prompt: Optional system prompt override
        max_tokens: Maximum tokens in response
        temperature: Sampling temperature
    
    Yields:
        Text chunks from LLM
    
    Raises:
        LLMConnectionError: If API call fails
    """
    # Validate inputs
    _validate_conversation_history(conversation_history)
    
    if system_prompt is not None and not isinstance(system_prompt, str):
        raise ValueError("system_prompt must be a string")
    
    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        raise LLMConnectionError("GROQ_API_KEY environment variable not set")
    
    try:
        client = Groq(api_key=groq_api_key)
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.extend(conversation_history)
        
        with client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            stream=True
        ) as response:
            for chunk in response:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
    
    except Exception as e:
        if isinstance(e, LLMConnectionError):
            raise
        raise LLMConnectionError(f"Streaming API error: {str(e)}")
