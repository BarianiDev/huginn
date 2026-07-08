from abc import ABC, abstractmethod
from huginn.core.models import Finding

class Collector(ABC):
    name: str = "base"

    @abstractmethod
    def collect(self, target: str) -> list[Finding]:
        ...