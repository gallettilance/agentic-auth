import json
import requests
import time

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


class InsufficientScopeError(Exception):
    """Raised when a tool call fails due to insufficient token scope"""
    def __init__(self, tool_name: str, required_scope: str, current_scopes: list[str] | None = None):
        self.tool_name = tool_name
        self.required_scope = required_scope
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



    def _request_scope_upgrade(self, required_scope: str, user_token: str) -> dict | None:
        """Request scope upgrade through the auth server's upgrade-scope endpoint"""
        payload = {
            "scopes": [required_scope]
        }

        headers = {
            "Authorization": f"Bearer {user_token}",
            "Content-Type": "application/json"
        }

        response = requests.post(f"{self.auth_endpoint}/api/upgrade-scope", json=payload, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Scope upgrade request failed: {response.status_code} - {response.text}")
            return None

    def _extract_scope_error_details(self, error_message: str) -> tuple[str, list]:
        """Extract required scope and current scopes from error message"""
        import json
        
        # Default fallbacks
        required_scope = "execute:commands"  # Most common restricted scope
        current_scopes = []
        
        try:
            # Try to parse JSON error message from MCP server
            if error_message.startswith('{') and error_message.endswith('}'):
                error_data = json.loads(error_message)
                if error_data.get("error_type") == "insufficient_scope":
                    required_scope = error_data.get("required_scope", required_scope)
                    current_scopes = error_data.get("user_scopes", current_scopes)
                    return required_scope, current_scopes
        except json.JSONDecodeError:
            pass
        
        # Try to parse common error patterns
        if "execute:commands" in error_message.lower():
            required_scope = "execute:commands"
        elif "read:files" in error_message.lower():
            required_scope = "read:files"
        elif "admin" in error_message.lower():
            required_scope = "admin:users"
            
        return required_scope, current_scopes

    def _get_user_context(self, session_id: str) -> dict:
        """Get user context for the current session"""
        # This would typically come from session storage or context
        # For now, return a default user context
        return {
            "user_email": "user@example.com",
            "user_id": f"user_{session_id}",
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

        # Execute the tool call - check result for authorization errors
        try:
            logger.info(f"executing tool call: {tool_name_str} with args: {tool_call.arguments}")
            result = await self.tool_runtime_api.invoke_tool(
                    tool_name=tool_name_str,
                    kwargs={
                        "session_id": session_id,
                        # get the arguments generated by the model and augment with toolgroup arg overrides for the agent
                        **(tool_call.arguments if isinstance(tool_call.arguments, dict) else {}),
                        **self.tool_name_to_args.get(tool_name_str, {}),
                        },
                    )
            logger.info(f"tool call {tool_name_str} completed with result: {result}")
            
            # Check if the result contains authorization error information
            if hasattr(result, 'content') and result.content:
                logger.info(f"📋 Tool result content: {str(result.content)[:200]}...")
                
                # Check if content is a list (like TextContentItem)
                if isinstance(result.content, list) and len(result.content) > 0:
                    first_item = result.content[0]
                    
                    # Check if the first item has text attribute (TextContentItem)
                    if hasattr(first_item, 'text') and hasattr(first_item, 'type') and first_item.type == 'text':
                        try:
                            import json
                            content_data = json.loads(first_item.text)
                            logger.info(f"📋 Parsed tool result content: {content_data}")

                            # Check if this is an authorization error response
                            if (isinstance(content_data, dict) and content_data.get("success") == False and 
                                content_data.get("error_type") == "insufficient_scope"):
                                
                                logger.info(f"🔐 Authorization error detected in tool result for {tool_name_str}")
                                
                                required_scope = content_data.get("required_scope", "unknown")
                                current_scopes = content_data.get("user_scopes", [])
                                
                                # Raise InsufficientScopeError to trigger the approval flow
                                raise InsufficientScopeError(tool_name_str, required_scope, current_scopes)
                                
                        except (json.JSONDecodeError, AttributeError, TypeError) as e:
                            # Not JSON or no match, continue with normal processing
                            logger.debug(f"Could not parse tool result as JSON: {e}")
                            pass
                
                # Also check if content is a string that might contain JSON
                elif isinstance(result.content, str):
                    try:
                        import json
                        content_data = json.loads(result.content)
                        logger.info(f"📋 Parsed string tool result content: {content_data}")

                        # Check if this is an authorization error response
                        if (isinstance(content_data, dict) and content_data.get("success") == False and 
                            content_data.get("error_type") == "insufficient_scope"):
                            
                            logger.info(f"🔐 Authorization error detected in string tool result for {tool_name_str}")
                            
                            required_scope = content_data.get("required_scope", "unknown")
                            current_scopes = content_data.get("user_scopes", [])
                            
                            # Raise InsufficientScopeError to trigger the approval flow
                            raise InsufficientScopeError(tool_name_str, required_scope, current_scopes)
                            
                    except (json.JSONDecodeError, AttributeError, TypeError) as e:
                        # Not JSON or no match, continue with normal processing
                        logger.debug(f"Could not parse string tool result as JSON: {e}")
                        pass
            
            # Return the result if no authorization error detected
            return result
            
        except InsufficientScopeError as scope_error:
            logger.info(f"🔐 InsufficientScopeError caught for {tool_name_str}: {scope_error}")
            
            # Return a structured error message that the chat app can detect
            error_message = f"InsufficientScopeError: Tool '{scope_error.tool_name}' requires scope '{scope_error.required_scope}' but token only has {scope_error.current_scopes}"
            
            return ToolInvocationResult(
                content=error_message
            )
        except Exception as e:
            error_message = str(e).lower()
            logger.info(f"tool call {tool_name_str} failed with exception: {error_message}")
            
            # Check if this is a scope/authorization error in the exception
            if any(keyword in error_message for keyword in [
                "insufficient scope", "unauthorized", "forbidden", 
                "access denied", "invalid token", "scope required"
            ]):
                logger.info(f"🔐 Authorization error detected in exception for {tool_name_str}: {str(e)}")
                
                # Extract scope details from error
                required_scope, current_scopes = self._extract_scope_error_details(str(e))
                
                # Return a structured error message that the chat app can detect
                error_message = f"InsufficientScopeError: Tool '{tool_name_str}' requires scope '{required_scope}' but token only has {current_scopes}"
                
                return ToolInvocationResult(
                    content=error_message
                )
            else:
                # Re-raise non-authorization errors immediately
                raise e

