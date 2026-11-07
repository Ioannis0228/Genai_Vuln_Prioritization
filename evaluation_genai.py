"""
This script provides functionality to evaluate unsupported claims in a dataset of explanations. It calculates metrics such as the total number of claims made, 
the number of unsupported claims. The evaluation results are returned as a dictionary containing the relevant metrics.
"""

import json
import pathlib
import re
from collections import Counter

EVIDENCE_TO_CLAIM_TYPE_MAP = {
    "CVSS score": ["CVSS"],
    "KEV": ["KEV"],
    "EPSS": ["EPSS"],
    "CSAF Advisory": ["CSAF_Advisory", "Vendor_Advisory", "Remediation_Step", "Mitigation"],
    "VEX Statement": ["VEX_Statement"],
}

def evaluate_unsupported_claims(dataset: list[dict], evidence_list: list[dict]) -> dict:
    """
    Evaluate unsupported claims in the provided dataset.

    Args:
        dataset (list[dict]): A list of dictionaries containing explanations with claims.
        evidence_list (list[dict]): A list of dictionaries containing evidence.

    Returns:
        dict: A dictionary containing the evaluation results.
    """
    total_samples_evaluated = 0
    total_claims_made = 0
    total_unsupported_claims = 0

    explanations = dataset.get("explanations", [])
    findings = evidence_list.get("findings", [])

    for idx, (explanation,finding) in enumerate(zip(explanations, findings)):
        total_samples_evaluated += 1

        # 1. Build a quick lookup dictionary for this finding's evidence: {evidence_id: evidence_dict}
        finding_evidence = finding.get("evidence", [])
        evidence_lookup = {ev["id"]: ev for ev in finding_evidence}
        
        # 2. Gather all claims from this explanation
        claims = explanation.get("why_prioritized_now", []) + explanation.get("what_to_do_next", [])
        total_claims_made += len(claims)
        
        # 3. Validate each claim's evidence ID and type
        for claim in claims:
            ev_id = claim.get("evidence_id")
            claim_type = claim.get("claim_type")
            
            if ev_id is not None:
                # Check A: Does the evidence_id exist in this finding's evidence list?
                if ev_id not in evidence_lookup:
                    print(f"[Index {idx}] Evidence ID {ev_id} not found in finding's evidence list.")
                    total_unsupported_claims += 1
                else:
                    # Check B: Does the evidence have the correct type?
                    actual_evidence_type = evidence_lookup[ev_id].get("type")
                    expected_types = EVIDENCE_TO_CLAIM_TYPE_MAP.get(actual_evidence_type, [actual_evidence_type])
                    
                    if claim_type not in expected_types:
                        print(
                            f"[Index {idx}] Type mismatch for evidence ID {ev_id}: "
                            f"Claim type is '{claim_type}', but evidence type is '{actual_evidence_type}'."
                        )
                        total_unsupported_claims += 1
            else:
                print(f"[Index {idx}] Claim has no evidence_id: {claim}")
                total_unsupported_claims += 1

    return {
        "total_samples_evaluated": total_samples_evaluated,
        "total_claims_made": total_claims_made,
        "total_unsupported_claims": total_unsupported_claims,
    }


if __name__ == "__main__":

    print("--- STARTING EVALUATION AUDIT ---\n")

    baseline_counter = Counter()
    # baseline_list = []
    baseline_paths = list(pathlib.Path("results/genai").glob("baseline_explanations_*.json"))
    for filepath in baseline_paths:
        sbom_id, top_k, snapshot_date = re.search(r'_(\d+)_(\d+)_(\d{4}-\d{2}-\d{2})$', filepath.stem).groups()
        context_file = pathlib.Path(f"results/genai/context_list_{sbom_id}_{top_k}_{snapshot_date}.json") 
        
        with open(context_file, "r", encoding="utf-8") as infile:
            context_list = json.load(infile)

        with open(filepath, "r", encoding="utf-8") as infile:
            dataset = json.load(infile)

        baseline_counter.update(evaluate_unsupported_claims(dataset, context_list))
        

    grounded_counter = Counter()
    # grounded_list = []
    grounded = list(pathlib.Path("results/genai").glob("grounded_explanations_*.json"))
    for filepath in grounded:
        sbom_id, top_k, snapshot_date = re.search(r'_(\d+)_(\d+)_(\d{4}-\d{2}-\d{2})$', filepath.stem).groups()
        context_file = pathlib.Path(f"results/genai/context_list_{sbom_id}_{top_k}_{snapshot_date}.json") 
        
        with open(context_file, "r", encoding="utf-8") as infile:
            context_list = json.load(infile)

        with open(filepath, "r", encoding="utf-8") as infile:
            dataset = json.load(infile)

        grounded_counter.update(evaluate_unsupported_claims(dataset, context_list))

    baseline_counter = dict(baseline_counter)
    grounded_counter = dict(grounded_counter)

    if baseline_counter["total_claims_made"] > 0:
        baseline_counter["unsupported_claim_rate"] = round((baseline_counter["total_unsupported_claims"] / baseline_counter["total_claims_made"]) * 100, 2)
    else:
        baseline_counter["unsupported_claim_rate"] = 0.0

    if grounded_counter["total_claims_made"] > 0:
        grounded_counter["unsupported_claim_rate"] = round((grounded_counter["total_unsupported_claims"] / grounded_counter["total_claims_made"]) * 100, 2)
    else:
        grounded_counter["unsupported_claim_rate"] = 0.0

    json_report = {
        "baseline": baseline_counter,
        "grounded": grounded_counter
    }
    json.dump(json_report, open("results/evaluation_genai.json", "w"), indent=4)

    print("\n--- FINAL METRICS REPORT ---\n")
    print(json.dumps(json_report, indent=4))