""" Service for handling GenAI generation requests """

from genai import *
import json
from pathlib import Path 

def generate_explanations(llm_client: LLMClient, sbom_id: int, top_k: int):
    """
    Generate explanations for the top_k findings in a given SBOM ID.
    
    Args:
        llm_client (LLMClient): The LLM client instance.
        sbom_id (int): The database ID of the ingested SBOM.
        top_k (int): The number of top findings to generate explanations for.
    """
    results = build_evidence_list(sbom_id=sbom_id, top_k=top_k)
    
    answer = llm_client.generate_response(instruction=CONSTRAINED_PROMPT, prompt=json.dumps(results), response_format=GroundedExplanationList)
    
    if answer:
        existing = list(Path("results").glob("grounded_explanations_*.json"))
        # print(answer.model_dump_json(indent=4))
        with open(f"results/grounded_explanations_{len(existing)+1:02d}.json", "a") as outfile:
            outfile.write(answer.model_dump_json(indent=4))