from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class AIProvider(ABC):
    """Abstract interface for LLM providers."""
    
    @abstractmethod
    def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """
        Sends the prompt to the LLM and expects a JSON response parsing to a Dict.
        Should handle network errors and JSON parsing errors internally, 
        returning an empty dict on catastrophic failure.
        """
        pass
