"""AWS Bedrock Agent service."""
import json
import logging
import uuid
from typing import Any, Dict, Optional, Tuple

import boto3

from ..config import Config

logger = logging.getLogger(__name__)


class BedrockServiceError(Exception):
    """Base exception for Bedrock service errors."""
    pass


class BedrockService:
    """Service for invoking AWS Bedrock Agents."""
    
    def __init__(self, agent_id: Optional[str] = None, alias_id: Optional[str] = None, region: Optional[str] = None):
        """Initialize Bedrock service."""
        self.agent_id = agent_id or Config.AGENT_ID
        self.alias_id = alias_id or Config.ALIAS_ID
        self.region = region or Config.AWS_REGION
        
        if not self.agent_id or not self.alias_id:
            logger.warning("[BedrockService] Missing agent_id or alias_id")
    
    def _get_client(self):
        """Get Bedrock Agent Runtime client."""
        return boto3.client("bedrock-agent-runtime", region_name=self.region)
    
    def invoke_agent(
        self,
        prompt: str,
        session_id: Optional[str] = None,
        enable_trace: bool = True
    ) -> Tuple[str, list[Dict[str, Any]]]:
        """
        Invoke a Bedrock Agent and collect streamed output.
        
        Args:
            prompt: Input text prompt
            session_id: Optional session ID (generated if not provided)
            enable_trace: Whether to enable tracing
            
        Returns:
            Tuple of (completion_text, raw_events)
            
        Raises:
            BedrockServiceError: If invocation fails
        """
        if not self.agent_id or not self.alias_id:
            raise BedrockServiceError("Missing AGENT_ID or ALIAS_ID")
        
        if not session_id:
            session_id = f"session-{uuid.uuid4()}"
        
        client = self._get_client()
        
        try:
            response = client.invoke_agent(
                agentId=self.agent_id,
                agentAliasId=self.alias_id,
                sessionId=session_id,
                inputText=prompt,
                enableTrace=enable_trace,
                streamingConfigurations={
                    "applyGuardrailInterval": 20,
                    "streamFinalResponse": True,
                }
            )
        except Exception as exc:
            logger.error(f"[BedrockService] Invocation failed: {exc}", exc_info=True)
            raise BedrockServiceError(f"Bedrock invocation failed: {exc}") from exc
        
        completion = ""
        raw_events: list[Dict[str, Any]] = []
        
        for event in response.get("completion", []):
            event_keys = list(event.keys())
            logger.debug(f"[BedrockService] Event keys: {event_keys}")
            raw_events.append(event)
            
            # Handle chunk events
            if "chunk" in event:
                raw = event["chunk"].get("bytes")
                if raw is not None:
                    decoded = raw.decode()
                    completion += decoded
                    logger.debug(f"[BedrockService] Chunk decoded: len={len(decoded)}")
            
            # Handle final response events
            if "finalResponse" in event:
                final_parts = event["finalResponse"].get("finalResponse", [])
                for part in final_parts:
                    text = part.get("text")
                    if text:
                        completion += text
                        logger.debug(f"[BedrockService] FinalResponse text: len={len(text)}")
            
            # Handle output text events
            if "outputText" in event:
                for ot in event.get("outputText", []):
                    text = ot.get("text")
                    if text:
                        completion += text
                        logger.debug(f"[BedrockService] OutputText: len={len(text)}")
            
            # Log trace events
            if "trace" in event:
                trace_event = event["trace"]
                for key, value in trace_event.get("trace", {}).items():
                    logger.debug(f"[BedrockService] Trace {key}: {value}")
        
        logger.info(f"[BedrockService] Invocation complete: completion_len={len(completion)}")
        return completion, raw_events
    
    def parse_completion(self, completion: str) -> Dict[str, Any]:
        """
        Parse JSON completion from Bedrock response.
        
        Args:
            completion: Raw completion text
            
        Returns:
            Parsed JSON dict
            
        Raises:
            BedrockServiceError: If parsing fails
        """
        try:
            return json.loads(completion)
        except json.JSONDecodeError as exc:
            logger.error(f"[BedrockService] Failed to parse completion as JSON: {exc}")
            raise BedrockServiceError(f"Failed to parse completion: {exc}") from exc

