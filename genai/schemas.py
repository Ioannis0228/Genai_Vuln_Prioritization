from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum

class ClaimType(str, Enum):
    CVSS = "CVSS"
    KEV = "KEV"
    EPSS = "EPSS"
    CSAF_Advisory = "CSAF_Advisory"
    VEX_Statement = "VEX_Statement"
    Vendor_Advisory = "Vendor_Advisory"
    Remediation_Step = "Remediation_Step"
    Mitigation = "Mitigation"
    Other = "Other"

class Claim(BaseModel):
    summary: str = Field(description="A detailed summary of the claim")
    claim_type: ClaimType = Field(description="Type of claim")
    value: Optional[str] = Field(description="The claim value")
    evidence_id: Optional[int] = Field(description="Evidence id supporting this claim")

class GroundedExplanation(BaseModel):
    Vulnerability: str = Field(description="CVE ID or identifier of the vulnerability being explained")
    component_purl: str = Field(description="PURL of the affected component")
    rank: int = Field(description="Rank of the finding")
    why_prioritized_now: List[Claim] = Field(description="Explanation of urgency")
    what_to_do_next: List[Claim] = Field(description="Actionable next steps")

class GroundedExplanationList(BaseModel):
    Product_Name: str = Field(description="Name of the product for which the explanations are generated")
    SBOM_id: int = Field(description="Database ID of the ingested SBOM")
    explanations: List[GroundedExplanation] = Field(description="List of grounded explanations for multiple findings")