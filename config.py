import os
from dataclasses import dataclass
import datetime 

def get_required_env(name: str) -> str:
    value = os.getenv(name)

    if not value:
        raise ValueError(f"{name} is not set.")

    return value

@dataclass(frozen=True)
class Config:
    """Configuration class for the application."""

    # Database configuration
    DATABASE_URL: str

    # OpenRouter API configuration
    OPENROUTER_KEY: str

    # Specify the model name for the LLM client
    # genai_model_name: str = "google/gemini-3.1-flash-lite"  
    genai_model_name: str = "google/gemini-3.5-flash-lite"  # Updated model name

    # Evaluation configuration
    k_values: tuple[int, ...] = (1, 3, 5, 10, 20, 50)
    evaluation_config_types: tuple[str, ...] = ("cvss", "epss", "cvss_epss", "fusion", "sbom_ablation", "epss_ablation", "kev_ablation")

    # Dates for evaluation snapshots
    start_date: datetime.date = datetime.date(2025, 4, 1)
    end_date: datetime.date = datetime.date(2026, 3, 31)

config = Config(DATABASE_URL=get_required_env("DATABASE_URL"), 
                OPENROUTER_KEY=get_required_env("OPENROUTER_KEY"),
            )