from typing import Any

from llama_stack.distribution.datatypes import Api

from .config import AuthAgentsImplConfig


async def get_provider_impl(config: AuthAgentsImplConfig, deps: dict[Api, Any]):
    from .agents import AuthAgentsImpl

    impl = AuthAgentsImpl(
        config,
        deps[Api.inference],
        deps[Api.vector_io],
        deps[Api.safety],
        deps[Api.tool_runtime],
        deps[Api.tool_groups],
        [],
    )
    await impl.initialize()
    return impl