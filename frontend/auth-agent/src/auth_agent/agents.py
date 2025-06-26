from .agent_instance import AuthChatAgent
from llama_stack.providers.inline.agents.meta_reference.persistence import AgentInfo

from llama_stack.providers.inline.agents.meta_reference.agents import (
    MetaReferenceAgentsImpl,
)

from llama_stack.apis.inference import Inference
from llama_stack.apis.safety import Safety
from llama_stack.apis.tools import ToolGroups, ToolRuntime
from llama_stack.apis.vector_io import VectorIO
from llama_stack.distribution.datatypes import AccessRule

from .config import AuthAgentsImplConfig


class AuthAgentsImpl(MetaReferenceAgentsImpl):
    def __init__(
        self,
        config: AuthAgentsImplConfig,
        inference_api: Inference,
        vector_io_api: VectorIO,
        safety_api: Safety,
        tool_runtime_api: ToolRuntime,
        tool_groups_api: ToolGroups,
        policy: list[AccessRule],
    ):
        super().__init__(
            config,
            inference_api,
            vector_io_api,
            safety_api,
            tool_runtime_api,
            tool_groups_api,
            policy,
        )
        self.config = config

    async def _get_agent_impl(self, agent_id: str) -> AuthChatAgent:
        agent_info_json = await self.persistence_store.get(
            key=f"agent:{agent_id}",
        )
        if not agent_info_json:
            raise ValueError(f"Could not find agent info for {agent_id}")

        try:
            agent_info = AgentInfo.model_validate_json(agent_info_json)
        except Exception as e:
            raise ValueError(f"Could not validate agent info for {agent_id}") from e

        return AuthChatAgent(
            agent_id=agent_id,
            agent_config=agent_info,
            inference_api=self.inference_api,
            safety_api=self.safety_api,
            vector_io_api=self.vector_io_api,
            tool_runtime_api=self.tool_runtime_api,
            tool_groups_api=self.tool_groups_api,
            persistence_store=(
                self.persistence_store
                if agent_info.enable_session_persistence
                else self.in_memory_store
            ),
            created_at=agent_info.created_at.isoformat(),
            policy=self.policy,
            auth_endpoint=self.config.auth_endpoint
        )
