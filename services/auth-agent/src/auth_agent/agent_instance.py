import json
import requests
import time
import os
import yaml

from llama_stack.apis.agents import AgentConfig, AgentTurnCreateRequest
from llama_stack.log import get_logger
from llama_stack.providers.inline.agents.meta_reference.agent_instance import ChatAgent
from llama_stack.providers.utils.telemetry import tracing
from llama_stack.distribution.datatypes import AccessRule

from llama_stack.apis.inference import (
    Inference,
    UserMessage,
    SamplingParams,
    TopPSamplingStrategy,
)

from llama_stack.apis.safety import Safety
from llama_stack.apis.tools import ToolGroups, ToolInvocationResult, ToolRuntime
from llama_stack.apis.vector_io import VectorIO
from llama_stack.providers.utils.kvstore import KVStore

from llama_stack.models.llama.datatypes import (
     BuiltinTool,
     ToolCall,
)

logger = get_logger(name=__name__, category="agents")


class AuthorizationError(Exception):
    """Raised when a tool call fails due to missing authentication (HTTP 401)"""
    def __init__(self, tool_name: str, mcp_server_url: str, message: str = "Authentication required"):
        self.tool_name = tool_name
        self.mcp_server_url = mcp_server_url
        self.message = message
        super().__init__(f"Authorization required for tool '{tool_name}' on server '{mcp_server_url}': {message}")


class InsufficientScopeError(Exception):
    """Raised when a tool call fails due to insufficient token scope (HTTP 403)"""
    def __init__(self, tool_name: str, required_scope: str, mcp_server_url: str, current_scopes: list[str] | None = None):
        self.tool_name = tool_name
        self.required_scope = required_scope
        self.mcp_server_url = mcp_server_url
        self.current_scopes = current_scopes if current_scopes is not None else []
        super().__init__(f"Tool '{tool_name}' requires scope '{required_scope}' but token only has {self.current_scopes}")


class AuthChatAgent(ChatAgent):
    def __init__(
            self,
            agent_id: str,
            agent_config: AgentConfig,
            inference_api: Inference,
            safety_api: Safety,
            tool_runtime_api: ToolRuntime,
            tool_groups_api: ToolGroups,
            vector_io_api: VectorIO,
            persistence_store: KVStore,
            created_at: str,
            policy: list[AccessRule],
            auth_endpoint: str,
            ):
        super().__init__(
                agent_id,
                agent_config,
                inference_api,
                safety_api,
                tool_runtime_api,
                tool_groups_api,
                vector_io_api,
                persistence_store,
                created_at,
                policy,
                )
        self.auth_endpoint = auth_endpoint
        # Cache for tool -> server URL mapping
        self._tool_server_cache = {}

    async def _get_mcp_server_for_tool(self, tool_name: str) -> str:
        """
        Determine which MCP server a tool belongs to using the tool's toolgroup_name.
        
        Args:
            tool_name: Name of the tool to find the server for
            
        Returns:
            MCP server URL for the tool
            
        Raises:
            ValueError: If tool or its toolgroup is not found
        """
        logger.info(f"🔍 Getting MCP server for tool: {tool_name}")
        
        # Check cache first
        if tool_name in self._tool_server_cache:
            cached_url = self._tool_server_cache[tool_name]
            logger.info(f"🔍 Found cached MCP server for {tool_name}: {cached_url}")
            return cached_url
            
        try:
            logger.info(f"🔍 Looking for tool {tool_name} in tool definitions")
            
            # Find the tool in our tool definitions to get its toolgroup_name
            tool_def = None
            for tool in self.tool_defs:
                if tool.tool_name == tool_name:
                    tool_def = tool
                    break
            
            if not tool_def:
                logger.error(f"🔍 Tool '{tool_name}' not found in tool definitions")
                raise ValueError(f"Tool '{tool_name}' not found in tool definitions")
            
            logger.info(f"🔍 Found tool definition for {tool_name}")
            
            # Get the toolgroup name from the tool definition
            toolgroup_name = getattr(tool_def, 'toolgroup_name', None)
            if not toolgroup_name:
                logger.error(f"🔍 Tool '{tool_name}' has no toolgroup_name")
                raise ValueError(f"Tool '{tool_name}' has no toolgroup_name")
            
            logger.info(f"🔍 Tool {tool_name} belongs to toolgroup: {toolgroup_name}")
            
            # Directly get the toolgroup details using its name/ID
            logger.info(f"🔍 Getting toolgroup details for: {toolgroup_name}")
            toolgroup_details = await self.tool_groups_api.get_tool_group(toolgroup_name)
            logger.info(f"🔍 Got toolgroup details: {toolgroup_details}")
            
            # Extract the MCP endpoint from the toolgroup
            mcp_endpoint = getattr(toolgroup_details, 'mcp_endpoint', None)
            if not mcp_endpoint:
                logger.error(f"🔍 Toolgroup '{toolgroup_name}' has no MCP endpoint")
                raise ValueError(f"Toolgroup '{toolgroup_name}' has no MCP endpoint")
            
            logger.info(f"🔍 Found MCP endpoint: {mcp_endpoint}")
            
            mcp_uri = getattr(mcp_endpoint, 'uri', str(mcp_endpoint))
            if not mcp_uri:
                logger.error(f"🔍 Toolgroup '{toolgroup_name}' has invalid MCP endpoint")
                raise ValueError(f"Toolgroup '{toolgroup_name}' has invalid MCP endpoint")
            
            logger.info(f"🔍 Final MCP URI for {tool_name}: {mcp_uri}")
            
            # Cache the result
            self._tool_server_cache[tool_name] = mcp_uri
            logger.info(f"Found MCP server for tool '{tool_name}' in toolgroup '{toolgroup_name}': {mcp_uri}")
            return mcp_uri
            
        except Exception as e:
            # Convert all errors to ValueError with context
            logger.error(f"🔍 Failed to determine MCP server for tool '{tool_name}': {e}")
            raise ValueError(f"Failed to determine MCP server for tool '{tool_name}': {e}") from e

    def _check_for_auth_errors(self, result: ToolInvocationResult, tool_name: str, mcp_server_url: str) -> None:
        """
        Check if the tool invocation result indicates authentication errors.
        
        Args:
            result: The result from tool invocation
            tool_name: Name of the tool that was invoked
            mcp_server_url: URL of the MCP server (dynamically discovered)
        """
        logger.info(f"🔍 Checking for auth errors in tool result for {tool_name}")
        
        if not result.content:
            logger.info(f"🔍 No content in result for {tool_name}")
            return
            
        try:
            # First, try to extract text content for FastMCP error format parsing
            text_content = None
            
            if isinstance(result.content, str):
                text_content = result.content
            elif isinstance(result.content, list):
                # Handle list of TextContentItem objects (common in Llama Stack)
                logger.info(f"🔍 Processing list content for {tool_name}")
                for item in result.content:
                    if hasattr(item, 'text'):
                        text_content = item.text
                        break  # Use first text content
                if not text_content:
                    logger.info(f"🔍 No text content found in list for {tool_name}")
                    return
            else:
                logger.info(f"🔍 Unknown content type for {tool_name}: {type(result.content)}")
                return
            
            # Check for FastMCP authorization errors using text parsing
            if text_content and self._is_authorization_error(text_content):
                logger.info(f"🔐 Detected FastMCP authorization error for {tool_name}")
                error_details = self._extract_authorization_error_details(text_content)
                
                if error_details.get("error_type") == "insufficient_scope":
                    logger.info(f"🔐 Detected insufficient_scope error for {tool_name}")
                    required_scope = error_details.get("required_scope", tool_name)
                    current_scopes = []  # FastMCP errors don't include current scopes
                    
                    raise InsufficientScopeError(
                        tool_name=tool_name,
                        required_scope=required_scope,
                        mcp_server_url=mcp_server_url,
                        current_scopes=current_scopes
                    )
                else:
                    logger.info(f"🚨 Detected authorization error for {tool_name} - RAISING AuthorizationError")
                    raise AuthorizationError(
                        tool_name=tool_name,
                        mcp_server_url=mcp_server_url,
                        message=f"Tool '{tool_name}' requires authentication: {text_content}"
                    )
            
            # Fallback: Try to parse as JSON for legacy error formats
            content_data = None
            try:
                if isinstance(result.content, str):
                    content_data = json.loads(result.content)
                elif isinstance(result.content, dict):
                    content_data = result.content
                elif isinstance(result.content, list):
                    for item in result.content:
                        if hasattr(item, 'text'):
                            try:
                                content_data = json.loads(item.text)
                                break
                            except json.JSONDecodeError:
                                continue
                
                if content_data:
                    # Check for legacy structured error formats
                    if content_data.get("error_type") == "insufficient_scope":
                        logger.info(f"🔐 Detected legacy insufficient_scope error for {tool_name}")
                        required_scope = content_data.get("required_scope", tool_name)
                        current_scopes = content_data.get("current_scopes", [])
                        
                        raise InsufficientScopeError(
                            tool_name=tool_name,
                            required_scope=required_scope,
                            mcp_server_url=mcp_server_url,
                            current_scopes=current_scopes
                        )
                    elif content_data.get("error_type") == "missing_authentication":
                        logger.info(f"🚨 Detected legacy missing_authentication error for {tool_name}")
                        raise AuthorizationError(
                            tool_name=tool_name,
                            mcp_server_url=mcp_server_url,
                            message=f"Tool '{tool_name}' requires authentication but no valid token was provided"
                        )
                
            except json.JSONDecodeError:
                pass  # Not JSON, that's fine
            
            logger.info(f"🔍 No auth error detected for {tool_name}")
                
        except (InsufficientScopeError, AuthorizationError):
            # Re-raise auth errors
            logger.info(f"🔥 Re-raising auth error for {tool_name}")
            raise
        except Exception as e:
            # Log but don't raise other parsing errors
            logger.debug(f"Could not parse tool result for auth errors: {e}")
    
    def _is_authorization_error(self, error_message: str) -> bool:
        """Check if error message indicates an authorization issue"""
        error_lower = error_message.lower()
        
        authorization_indicators = [
            "authorizationerror",
            "authorization required",
            "authorization failed",
            "insufficientscopeerror", 
            "insufficient scope",
            "access denied",
            "unauthorized",
            "permission denied",
            "forbidden"
        ]
        
        return any(indicator in error_lower for indicator in authorization_indicators)
    
    def _extract_authorization_error_details(self, error_message: str) -> dict:
        """Extract details from authorization error messages"""
        import re
        import os
        
        error_lower = error_message.lower()
        
        # Default values
        tool_name = "unknown_tool"
        required_scope = "execute_command"  # Most common restricted scope
        error_type = "authorization"
        approval_status = "unknown"
        approval_requested = False
        mcp_server_url = None
        auth_server_url = None
        
        # Check if this is the new FastMCP AuthorizationError with scope details
        # Format: "Authorization failed: Access denied: Tool 'list_files' requires scope 'list_files' but only scopes [] are available"
        if ("AuthorizationError" in error_message or "Authorization failed" in error_message) and "requires scope" in error_message:
            error_type = "insufficient_scope"
            approval_requested = True  # This is scope-related, needs token exchange
            
            # Extract tool name from the new FastMCP format
            # Pattern: "Tool 'tool_name' requires scope"
            tool_match = re.search(r"Tool ['\"]?(\w+)['\"]?\s+requires scope", error_message)
            if tool_match:
                tool_name = tool_match.group(1)
            
            # Extract required scope from the new FastMCP format  
            # Pattern: "requires scope 'scope_name'"
            scope_match = re.search(r"requires scope ['\"]?([^'\"]+)['\"]?", error_message)
            if scope_match:
                required_scope = scope_match.group(1)
            
            # For FastMCP errors, we need to determine the MCP server URL
            # Since it's not in the error message, we'll discover it dynamically
            # Note: MCP server URL should be determined at runtime from toolgroups
            mcp_server_url = None  # Will be determined dynamically at runtime
            
            return {
                "error_type": error_type,
                "tool_name": tool_name,
                "required_scope": required_scope,
                "mcp_server_url": mcp_server_url,
                "auth_server_url": None,  # Will be discovered by chat app
                "original_error": error_message,
                "approval_requested": approval_requested,
                "approval_status": "pending_token_exchange"
            }
        
        return {
            "error_type": error_type,
            "tool_name": tool_name,
            "required_scope": required_scope,
            "mcp_server_url": mcp_server_url,
            "auth_server_url": auth_server_url,
            "original_error": error_message,
            "approval_requested": approval_requested,
            "approval_status": approval_status
        }

    async def execute_tool_call_maybe(
            self,
            session_id: str,
            tool_call: ToolCall,
            ) -> ToolInvocationResult:
        
        tool_name = tool_call.tool_name
        registered_tool_names = {}
        for tool in self.tool_defs:
            registered_tool_names[tool.tool_name] = tool
        if tool_name not in registered_tool_names:
            raise ValueError(
                    f"Tool {tool_name} not found in provided tools, registered tools: {', '.join([str(x) for x in registered_tool_names])}"
                    )
        
        if isinstance(tool_name, BuiltinTool):
            if tool_name == BuiltinTool.brave_search:
                tool_name_str = "brave_search"
            else:
                tool_name_str = tool_name.value
        else:
            tool_name_str = tool_name

        # Get the MCP server URL for this tool dynamically
        mcp_server_url = await self._get_mcp_server_for_tool(tool_name_str)

        # Execute the tool call
        try:
            logger.info(f"🔧 Executing tool call: {tool_name_str} with args: {tool_call.arguments}")
            result = await self.tool_runtime_api.invoke_tool(
                    tool_name=tool_name_str,
                    kwargs={
                        **(tool_call.arguments if isinstance(tool_call.arguments, dict) else {}),
                        **self.tool_name_to_args.get(tool_name_str, {}),
                        },
                    )
            logger.info(f"✅ Tool call {tool_name_str} completed successfully")
            logger.info(f"🔧 Tool result type: {type(result)}")
            logger.info(f"🔧 Tool result: {result}")
            
            # Check for authentication/authorization errors
            logger.info(f"🔍 About to check for auth errors for {tool_name_str}")
            self._check_for_auth_errors(result, tool_name_str, mcp_server_url)
            logger.info(f"🔍 Auth error check completed for {tool_name_str}")
            
            # Return the result if no authentication/authorization errors
            return result
            
        except AuthorizationError as auth_error:
            logger.error(f"🚨 Authorization error for {tool_name_str}: {auth_error}")
            # Return error as ToolInvocationResult with correct structure
            from llama_stack_client.types import ToolInvocationResult
            error_content = f"AuthorizationError: Authorization required for tool '{tool_name_str}' on server '{mcp_server_url}': {auth_error.message}"
            return ToolInvocationResult(
                content=error_content,
                error_code=401,
                error_message=f"Authorization required for tool '{tool_name_str}'"
            )
            
        except InsufficientScopeError as scope_error:
            logger.info(f"🔐 Insufficient scope for {tool_name_str}: {scope_error}")
            # Return error as ToolInvocationResult with correct structure
            from llama_stack_client.types import ToolInvocationResult
            error_content = f"InsufficientScopeError: Tool '{tool_name_str}' requires scope '{scope_error.required_scope}' on server '{mcp_server_url}' but current scopes are {scope_error.current_scopes}"
            return ToolInvocationResult(
                content=error_content,
                error_code=403,
                error_message=f"Insufficient scope for tool '{tool_name_str}': requires '{scope_error.required_scope}'"
            )
            
        except Exception as e:
            # All other errors are surfaced as-is without modification
            logger.info(f"❌ Tool call {tool_name_str} failed with exception: {str(e)}")
            raise e

