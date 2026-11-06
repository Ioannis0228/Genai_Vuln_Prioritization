""" 
This module provides functionality to build a list of context objects for a given SBOM ID. It retrieves advisories, VEX statements, 
KEV snapshots, EPSS snapshots, and evidence from the database, and constructs a structured context list for the findings provided. 
The context list includes relevant advisories, evidence, and other information related to the findings.
"""

from database import SessionLocal, vex_statement_component, SBOM, EPSSsnapshot, KEVsnapshot, Vulnerabilities, Components, VEXstatements, CSAFadvisories, Evidence, csaf_vulnerability, execute_select, get_rows_by_column_in, get_latest_snapshots
from sqlalchemy import or_
import json
import pathlib
from datetime import date, datetime
from packageurl import PackageURL
from collections import defaultdict

def build_context_list(sbom_id: int, findings: list, snapshot_date: date) -> dict:
    """ Builds a list of context objects for a given SBOM ID.
    
    Args:
        sbom_id (int): The ID of the SBOM for which to build the context list.
        findings (list): A list of findings to include in the context.
        snapshot_date (date): The date for which to retrieve the findings.
    Returns:
        results_dict (dict): A dictionary containing the context information for the top findings.
    """
    
    cve_ids = {finding['cve_id'] for finding in findings}

    with SessionLocal() as session:
        raw_advisories = execute_select(session, selected_columns=[CSAFadvisories.id, CSAFadvisories.csaf_id, CSAFadvisories.data, Vulnerabilities.cve_id],
                                        where_conditions=[Vulnerabilities.cve_id.in_(cve_ids)],
                                        joins=[(csaf_vulnerability, csaf_vulnerability.c.csaf_id == CSAFadvisories.id),
                                               (Vulnerabilities, csaf_vulnerability.c.vulnerability_id == Vulnerabilities.id)]
                                        )

        vex_statements = execute_select(
                    session=session,
                    selected_columns=[VEXstatements.id, Vulnerabilities.cve_id, Components.purl, VEXstatements.sbom_id, VEXstatements.timestamp],
                    where_conditions=[or_(VEXstatements.sbom_id == sbom_id, VEXstatements.sbom_id.is_(None)), Vulnerabilities.cve_id.in_(cve_ids),
                                      VEXstatements.timestamp <= datetime.combine(snapshot_date, datetime.max.time())],
                    joins=[(Vulnerabilities, VEXstatements.vulnerability == Vulnerabilities.id),
                            (vex_statement_component, VEXstatements.id == vex_statement_component.c.statement_id),
                            (Components, Components.id == vex_statement_component.c.component_id)]
                )
        
        kev_rows = get_latest_snapshots(session=session, table=KEVsnapshot,
                                        cve_ids=cve_ids, date_column=KEVsnapshot.snapshot_date,
                                        selected_columns=[KEVsnapshot.id, KEVsnapshot.cve_id],
                                        date=snapshot_date
                                        )
        
        epss_rows = get_latest_snapshots(session=session, table=EPSSsnapshot,
                                        cve_ids=cve_ids,  date_column=EPSSsnapshot.score_date,
                                        selected_columns=[EPSSsnapshot.id,EPSSsnapshot.cve_id],
                                        date=snapshot_date
                                        )
        

        evidence = execute_select(session, selected_columns=[Evidence],
                                    where_conditions=[Evidence.cve_id.in_(cve_ids)],
                                    joins=[(Vulnerabilities, Evidence.cve_id == Vulnerabilities.cve_id)]
                                    )
        
        product_name = get_rows_by_column_in(session=session, 
                                             tables=SBOM, 
                                             selected_columns=[SBOM.product_name], 
                                             filter_column=SBOM.id,
                                             filter_values=[sbom_id],
        )

    kev_data = {cve_id: id for id, cve_id in kev_rows}
    epss_data = {cve_id: id for id, cve_id in epss_rows}

    advisories = defaultdict(list)
    for id, csaf_id, data, cve_id in raw_advisories:
        advisories[cve_id].append({
            'id': id, 
            'data': data, 
            'csaf_id': csaf_id
        })

    VEX_map = {}
    for id, cve_id, purl, sbom_id, timestamp in vex_statements:
            key = (cve_id, purl)
            candidate = {
                "id": id,
                "sbom_id": sbom_id,
                "timestamp": timestamp
            }
    
            current = VEX_map.get(key)
            if current is None:
                VEX_map[key] = candidate
                continue
    
            # SBOM-specific statements take precedence over global statements
            if candidate["sbom_id"] == sbom_id and current["sbom_id"] is None:
                VEX_map[key] = candidate
    
            elif candidate["sbom_id"] is None and current["sbom_id"] == sbom_id:
                continue
    
            elif timestamp > current["timestamp"]:
                VEX_map[key] = candidate

    results = []

    if findings:

        for finding in findings:
            relevant_advisories = []
            for advisory in advisories.get(finding['cve_id'], []):
                if applicable_advisory(purl=finding['component_purl'], cve_id=finding['cve_id'], advisory=advisory['data']):
                    if date.fromisoformat(advisory['data'].get("document", {}).get("tracking", {}).get("initial_release_date")[:10]) <= snapshot_date:
                        relevant_advisories.append(advisory)

            match_evidence = set()
            if epss_id :=epss_data.get(finding['cve_id']):
                match_evidence.add(("EPSS", epss_id))
            if kev_id := kev_data.get(finding['cve_id']):
                match_evidence.add(("KEV", kev_id))
            if vex_id := VEX_map.get((finding['cve_id'], finding['component_purl'])):
                match_evidence.add(("VEX", vex_id))
            for advisory in relevant_advisories:
                match_evidence.add(("CSAF Advisory", advisory['id']))

            relevant_evidence = [
                item[0] for item in evidence
                if (item[0].evidence_type, item[0].source_record_id) in match_evidence 
                or (item[0].evidence_type == "CVSS score" and item[0].cve_id == finding['cve_id'])
            ]

            results.append({
                "finding_id": finding['finding_id'],
                "component_purl": finding['component_purl'],
                "CVE": finding['cve_id'],
                "current_assessment": {
                    "score": finding['score'],
                    "rank": finding['rank'],
                    "priority": finding['priority']
                },
                "evidence": [
                    {
                        "id": evidence.id,
                        "cve_id": evidence.cve_id,
                        "type": evidence.evidence_type,
                        "source": evidence.source,
                        "text_snippet": evidence.text_snippet,
                    } for evidence in relevant_evidence
                ],
                "advisories": [
                    {
                        "csaf_id": advisory['csaf_id'],
                        "title": advisory['data'].get("document", {}).get("title", ""),
                        "advisory_details": {
                            "cve": finding['cve_id'],
                            "title": [vuln.get('title','') for vuln in advisory['data'].get("vulnerabilities", [{}]) if vuln.get("cve") == finding['cve_id']],
                            "notes": advisory['data'].get("document", {}).get("notes", ""),
                            "remediations": [
                                {
                                    "category": r.get("category", ""),
                                    "details": r.get("details", ""),
                                    "url": r.get("url", ""),
                                } for vuln in advisory['data'].get("vulnerabilities", [{}]) 
                                if vuln.get("cve") == finding['cve_id'] 
                                for r in vuln.get("remediations", [])
                            ],
                            "initial_release_date": advisory['data'].get("document", {}).get("tracking", {}).get("initial_release_date", ""),
                        }
                    } for advisory in relevant_advisories
                ]
            })

    results_dict = { 
        "Product_Name": product_name[0][0], 
        "SBOM_id": sbom_id, 
        "findings": results,
        }

    path = pathlib.Path(f"results/genai/context_list_{sbom_id}_{len(findings)}_{snapshot_date}.json")
    path.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
    with open(path, "w") as outfile:
        json.dump(results_dict, outfile, indent=2)

    return results_dict if findings else {}


def applicable_advisory(purl: str, cve_id: str, advisory: dict) -> bool:
    """Check if the given purl matches any CSAF advisory product URL.
    
    Args:
        purl (str): The package URL of the component.
        cve_id (str): The CVE ID of the finding.
        advisory (dict): The CSAF advisory data.

    Returns:
        bool: True if the purl matches any product URL in the advisory, False otherwise.
    """
    try:
        target = PackageURL.from_string(purl)
    except Exception as e:
        print(f"Invalid target purl: {e}")
        return False

    products = {}

    def parse_node(node):
        if not isinstance(node, dict):
            return
        
        pid = node.get("product_id")
        helper = node.get("product_identification_helper", {})
        ppurl = helper.get("purl")

        if pid and ppurl:
            products[pid] = ppurl

        # Check nested product dictionaries if present
        if "product" in node and isinstance(node["product"], dict):
            parse_node(node["product"])

    def walk(obj):
        if isinstance(obj, dict):
            parse_node(obj)
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)

    product_tree = advisory.get("product_tree", {})
    walk(product_tree)


    matching_ids = set()
    for pid, ppurl in products.items():
        try:
            candidate = PackageURL.from_string(ppurl)
        except ValueError:
            continue

        # Match type, namespace, and name.
        if (target.type == candidate.type 
            and target.namespace == candidate.namespace
            and target.name == candidate.name):
            matching_ids.add(pid)
    
    # Check vulnerabilities
    for vuln in advisory.get("vulnerabilities", []):
        if vuln.get("cve") != cve_id:
            continue

        statuses = vuln.get("product_status", {})
        relevant_statuses = [
            "known_affected",
            "fixed",
            "known_not_affected",
            "under_investigation",
        ]

        for status in relevant_statuses:
            status_pids = statuses.get(status, [])
            
            # Check if any status ID matches our component ID after stripping the prefix
            matched = False
            for spid in status_pids:
                parts = spid.split(":", 1)
                real_pid = parts[1] if len(parts) > 1 else parts[0]

                if real_pid in matching_ids or spid in matching_ids:
                    matched = True
                    break

            if matched:
                if status in ("known_affected", "fixed", "under_investigation"):
                    return True

    return False