""" 
This module provides functionality to build a list of context objects for a given SBOM ID. It retrieves findings from the database, 
including associated evidence items and CSAF advisories, and constructs a structured list of dictionaries containing relevant information for each finding.
"""

from database import SessionLocal, SBOM, Finding, Vulnerabilities, VulnerabilityEnrichment, execute_select, get_rows_by_column_in
from sqlalchemy.orm import selectinload, joinedload
import json
import pathlib

def build_context_list(sbom_id: int, top_k: int) -> dict:
    """ Builds a list of context objects for a given SBOM ID.
    
    Args:
        sbom_id (int): The ID of the SBOM for which to build the context list.
        top_k (int): The number of top findings to retrieve based on their rank.
    Returns:
        results_dict (dict): A dictionary containing the context information for the top findings.
    """

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

        cwe = execute_select(session=session,
                            selected_columns=[VulnerabilityEnrichment.cve_id, 
                                              VulnerabilityEnrichment.entity_id],
                            where_conditions=[VulnerabilityEnrichment.cve_id.in_([finding.vulnerability.cve_id for finding, in findings]),
                                                (VulnerabilityEnrichment.data_type == "CWE")],
        )
        
        product_name = get_rows_by_column_in(session=session, 
                                             tables=SBOM, 
                                             selected_columns=[SBOM.product_name], 
                                             filter_column=SBOM.id,
                                             filter_values=[sbom_id],
        )

    results = []

    if findings:

        for (finding,) in findings:
            if finding.why_ranked == "Not yet evaluated":
                raise ValueError(f"Please run prioritization for the SBOM with ID {sbom_id} before generating explanations.")

            target_cve = finding.vulnerability.cve_id

            relevant_advisories = []

            for advisory in finding.vulnerability.csaf_advisories:
                if not isinstance(advisory.data, dict):
                    continue  # Skip if advisory data is not a dictionary

                raw_vulns = advisory.data.get("vulnerabilities", [])
                matching_vuln = next(
                    (v for v in raw_vulns if v.get("cve") == target_cve), 
                    None  # Falls back to None if not found
                )

                if not matching_vuln:
                    continue  # Skip if no matching vulnerability is found

                tracking = (advisory.data.get("document", {}).get("tracking", {}))
                release_date = tracking.get("current_release_date")

                if not release_date: 
                    release_date = tracking.get("initial_release_date")

                relevant_advisories.append({
                    "advisory": advisory, 
                    "matching_vuln": matching_vuln, 
                    "release_date": release_date or "",
                })

            relevant_advisories.sort(key=lambda x: x["release_date"], reverse=True) # Sort advisories by release date in descending order
            selected_advisories = relevant_advisories[:10] # Limit to the 10 most recent advisories
            selected_advisory_ids = {item["advisory"].id for item in selected_advisories}

            advisories_data = []

            for item in selected_advisories: 
                advisory = item["advisory"] 
                matching_vuln = item["matching_vuln"] 
                release_date = item["release_date"] 
                remediations = [ 
                    { 
                    "category": r.get("category", ""),
                    "details": r.get("details", ""), 
                    "url": r.get("url", ""), 
                    } for r in matching_vuln.get("remediations", []) 
                ] 
                advisories_data.append({ 
                    "csaf_id": advisory.csaf_id, 
                    "advisory_details": {
                        "cve": matching_vuln.get("cve", ""),
                        "title": matching_vuln.get("title", ""),
                        "notes": matching_vuln.get("notes", ""), 
                        "remediations": remediations, 
                        "current_release_date": release_date,
                        }
                    }
                )

            # Get the latest non-CSAF evidence items and the selected CSAF evidence items
            sorted_evidence = sorted(finding.evidence_items, key=lambda x: x.id)  # Sort by evidence ID
            selected_evidence = []
            latest_non_csaf = {}

            for evidence in sorted_evidence:
                # Keep every non-CSAF evidence item 
                if evidence.evidence_type != "CSAF Advisory": 
                    latest_non_csaf[evidence.evidence_type] = evidence
                else:
                    if evidence.source_record_id in selected_advisory_ids: 
                        selected_evidence.append(evidence)

            selected_evidence.extend(list(latest_non_csaf.values()))


            results.append(
                { 
                    "finding_id": finding.id,
                    "component_purl": (finding.component.purl if finding.component else None),
                    "vulnerability": {
                        "CVE": finding.vulnerability.cve_id,
                        "CWE": [item.entity_id for item in cwe if item.cve_id == finding.vulnerability.cve_id],
                    },
                    "current_assesment":{
                        "rank": finding.rank,
                        "priority": finding.priority,
                        "why_ranked": finding.why_ranked
                    },
                    "evidence": [ 
                        { 
                            "id": evidence.id, 
                            "cve_id": evidence.cve_id, 
                            "type": evidence.evidence_type, 
                            "source": evidence.source, 
                            "text_snippet": evidence.text_snippet,
                        } for evidence in selected_evidence 
                    ], 
                    "advisories": advisories_data, 
                }
            ) 

        results_dict = { 
            "Product_Name": product_name[0][0], 
            "SBOM_id": sbom_id, 
            "findings": results,
        }

    path = pathlib.Path(f"results/genai/evidence_list_{sbom_id}_{top_k}.json")
    path.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
    with open(path, "w") as outfile:
        json.dump(results, outfile, indent=2)

    return results_dict if findings else {}