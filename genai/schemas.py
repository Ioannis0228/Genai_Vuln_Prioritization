from pydantic import BaseModel, Field
from typing import List

# --- Scope: Claims & Explanations ---
class Prioritization(BaseModel):
    reason_type: str = Field(description="Type of prioritization reason, e.g., CVSS, KEV, EPSS, CSAF_Advisory")
    statement: str = Field(description="Statement explaining why the vulnerability is prioritized now")
    evidence_ids: List[str] = Field(description="List of evidence ids supporting this prioritization reason")

class Remediation(BaseModel):
    action_type: str = Field(description="Type of remediation action, e.g., Patch, Mitigation, Workaround")
    statement: str = Field(description="Statement explaining what to do next for remediation")
    evidence_ids: List[str] = Field(description="List of evidence ids supporting this remediation action")

class Claim(BaseModel):
    summary: str = Field(description="A concise summary of the claim")
    claim_type: str = Field(description="e.g., KEV, EPSS, CSAF_Advisory, etc.")
    value: str = Field(description="The claim value")
    evidence_id: str = Field(description="Evidence id supporting this claim")

class GroundedExplanation(BaseModel):
    Vulnerability: str = Field(description="CVE ID or identifier of the vulnerability being explained")
    component_purl: str = Field(description="PURL of the affected component")
    why_prioritized_now: List[Prioritization] = Field(description="Explanation of urgency, MUST cite evidence_ids")
    what_to_do_next: List[Remediation] = Field(description="Actionable next steps, MUST cite evidence_ids")
    claims: List[Claim] = Field(description="List of claims made in the explanation, each tied to an evidence_id")

class GroundedExplanationList(BaseModel):
    explanations: List[GroundedExplanation] = Field(description="List of grounded explanations for multiple vulnerabilities")