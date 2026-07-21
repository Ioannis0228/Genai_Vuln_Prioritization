""" 
This module provides functionality to build a list of evidence objects for a given SBOM ID. It retrieves findings from the database, 
including associated evidence items and CSAF advisories, and constructs a structured list of dictionaries containing relevant information for each finding.
"""

from database import SessionLocal, Finding, Vulnerabilities, execute_select
from sqlalchemy.orm import selectinload, joinedload

def build_evidence_list(sbom_id: int, top_k: int) -> list[dict]:
    """ Builds a list of evidence objects for a given SBOM ID."""

    
    with SessionLocal() as session:
        findings = execute_select(session=session,
                                  selected_columns=[Finding],
                                  where_conditions=[Finding.sbom_id == sbom_id],
                                  order_by=[Finding.rank.asc()],
                                  options=[selectinload(Finding.evidence_items),
                                           joinedload(Finding.vulnerability).selectinload(Vulnerabilities.csaf_advisories),
                                           selectinload(Finding.component)],
                                  limit=top_k,
        )

    results = []
    if findings:

        for (finding,) in findings:

            target_cve = finding.vulnerability.cve_id
        
            advisories_data = []
            for advisory in finding.vulnerability.csaf_advisories:
                raw_vulns = advisory.data.get("vulnerabilities", []) if isinstance(advisory.data, dict) else []
            
                matching_vuln = next(
                    (v for v in raw_vulns if v.get("cve") == target_cve), 
                    None  # Falls back to None if not found
                )

                if matching_vuln:
                    remediations = [
                        {
                            "category": r.get("category", ""),
                            "details": r.get("details", ""),
                            "url": r.get("url", ""),
                        }
                        for r in matching_vuln.get("remediations", [])
                    ]

                    vulnerability_details = { 
                        "cve": matching_vuln.get("cve", ""),
                        "title": matching_vuln.get("title", ""),
                        "notes": matching_vuln.get("notes", ""),
                        "remediations": remediations,
                    }
            
                advisories_data.append({
                    "csaf_id": advisory.csaf_id,
                    "vulnerability_details": vulnerability_details
                })

            results.append({
                "finding_id": finding.id,
                "component_purl": finding.component.purl if finding.component else None,
                "rank": finding.rank,
                "why_ranked": finding.why_ranked,
                "evidence": [
                        {
                            "id": evidence.id,
                            "cve_id": evidence.cve_id,
                            "type": evidence.evidence_type,
                            "source": evidence.source,
                            "text_snippet": evidence.text_snippet,
                        }
                        for evidence in finding.evidence_items
                    ],
                "advisories": advisories_data
                }
            )

    return results if findings else []