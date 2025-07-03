from typing import Any
from llama_stack.providers.inline.agents.meta_reference.config import (
    MetaReferenceAgentsImplConfig,
)

from pydantic import BaseModel

class AuthAgentsImplConfig(MetaReferenceAgentsImplConfig):
    """Authorization agent configuration"""
    auth_endpoint: str
    
    @classmethod
    def sample_run_config(cls, __distro_dir__: str) -> dict[str, Any]:
        config = super().sample_run_config(__distro_dir__)
        return config

    class Config:
        extra = "forbid"
