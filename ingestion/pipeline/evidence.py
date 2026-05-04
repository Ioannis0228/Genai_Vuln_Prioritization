from collections import defaultdict

from sqlalchemy import tuple_

from database import (
    SessionLocal,
    Vulnerabilities,
    EPSSsnapshot,
    KEVsnapshot,
    CSAFadvisories,
    Finding,
    finding_evidence,
    csaf_vulnerability,
    execute_select,
    get_rows_by_column_in,
)


def create_Evidence(sbom_id):

    new_evidence_items = []
    existing_evidence_items = []

    with SessionLocal() as session:

        current_findings = execute_select(
            session = session,
            selected_columns = [Finding.id, Finding.component_id, Finding.vulnerability_id],
            where_conditions = [Finding.sbom_id == sbom_id])

        if not current_findings:
            return new_evidence_items, existing_evidence_items

        current_pairs = {
            (finding.component_id, finding.vulnerability_id)
            for finding in current_findings
        }

        previous_findings = execute_select(
            session = session,
            selected_columns = [Finding.id, Finding.component_id, Finding.vulnerability_id],
            where_conditions = [
                Finding.sbom_id != sbom_id,
                tuple_(Finding.component_id, Finding.vulnerability_id).in_(current_pairs),
            ]
        )

        previous_finding_ids = [finding.id for finding in previous_findings]
        previous_by_pair = {
            (finding.component_id, finding.vulnerability_id): finding.id
            for finding in previous_findings
        }

        if previous_finding_ids:
            evidence_links = get_rows_by_column_in(
                session=session,
                tables=finding_evidence,
                filter_column=finding_evidence.c.finding_id,
                filter_values=previous_finding_ids,
                selected_columns=[finding_evidence.c.finding_id, finding_evidence.c.evidence_id]
            )

            evidence_ids_by_finding = defaultdict(list)
            for finding_id, evidence_id in evidence_links:
                evidence_ids_by_finding[finding_id].append(evidence_id)

            for finding in current_findings:
                previous_finding_id = previous_by_pair.get((finding.component_id, finding.vulnerability_id))
                if previous_finding_id is None:
                    continue

                for evidence_id in evidence_ids_by_finding.get(previous_finding_id, []):
                    existing_evidence_items.append({
                        "finding_id": finding.id,
                        "evidence_id": evidence_id,
                    })

        new_findings = [
            finding
            for finding in current_findings
            if (finding.component_id, finding.vulnerability_id) not in previous_by_pair
        ]

        if not new_findings:
            return new_evidence_items, existing_evidence_items

        vulnerability_ids = {finding.vulnerability_id for finding in new_findings}

        vulnerability_rows = get_rows_by_column_in(
            session=session,
            tables=Vulnerabilities,
            filter_column=Vulnerabilities.id,
            filter_values=vulnerability_ids,
            selected_columns=[
                Vulnerabilities.id,
                Vulnerabilities.cve_id,
                Vulnerabilities.cvss_score,
                Vulnerabilities.cvss_version,
                Vulnerabilities.cvss_source,
            ]
        )
        vulnerability_map = {row.id: row for row in vulnerability_rows}

        cve_ids = {row.cve_id for row in vulnerability_rows}

        epss_rows = get_rows_by_column_in(
            session=session,
            tables=EPSSsnapshot,
            filter_column=EPSSsnapshot.cve_id,
            filter_values=cve_ids,
            selected_columns=[EPSSsnapshot.cve_id, EPSSsnapshot.epss_score, EPSSsnapshot.date]
        )
        epss_map = {row.cve_id: row for row in epss_rows}

        kev_rows = get_rows_by_column_in(
            session=session,
            tables=KEVsnapshot,
            filter_column=KEVsnapshot.cve_id,
            filter_values=cve_ids,
            selected_columns=[KEVsnapshot.cve_id, KEVsnapshot.dateAdded]
        )
        kev_map = {row.cve_id: row for row in kev_rows}

        advisory_rows = execute_select(
            session=session,
            selected_columns=[
                csaf_vulnerability.c.vulnerability_id,
                CSAFadvisories.csaf_id,
                CSAFadvisories.description,
            ],
            joins=[
                (csaf_vulnerability, csaf_vulnerability.c.csaf_id == CSAFadvisories.id)
            ],
            where_conditions=[
                csaf_vulnerability.c.vulnerability_id.in_(vulnerability_ids)
            ]
        )

        advisories_by_vulnerability = defaultdict(list)
        for vulnerability_id, csaf_id, description in advisory_rows:
            advisories_by_vulnerability[vulnerability_id].append({
                "csaf_id": csaf_id,
                "description": description,
            })

        for finding in new_findings:
            vulnerability = vulnerability_map.get(finding.vulnerability_id)
            if vulnerability is None:
                continue

            cve_id = vulnerability.cve_id

            if vulnerability.cvss_score is not None:
                new_evidence_items.append({
                    "finding_id": finding.id,
                    "evidence_type": "CVSS",
                    "source": vulnerability.cvss_source.upper() if vulnerability.cvss_source else None,
                    "text_snippet": (
                        f"CVSS {vulnerability.cvss_version or ''} "
                        f"score for {cve_id}: "
                        f"{vulnerability.cvss_score}"
                    ),
                    "url_or_ref": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })

            epss_data = epss_map.get(cve_id)
            if epss_data:
                new_evidence_items.append({
                    "finding_id": finding.id,
                    "evidence_type": "EPSS",
                    "source": "First.org EPSS API",
                    "text_snippet": (
                        f"EPSS score for {cve_id}: "
                        f"{epss_data.epss_score} "
                        f"on {epss_data.date}"
                    ),
                    "url_or_ref": f"https://api.first.org/data/v1/epss?cve={cve_id}"
                })

            kev_data = kev_map.get(cve_id)
            if kev_data:
                new_evidence_items.append({
                    "finding_id": finding.id,
                    "evidence_type": "KEV",
                    "source": "CISA KEV Catalog",
                    "text_snippet": (
                        f"KEV entry for {cve_id}: "
                        f"Added to catalog on {kev_data.dateAdded}"
                    ),
                    "url_or_ref": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                })

            for advisory in advisories_by_vulnerability.get(finding.vulnerability_id, []):
                new_evidence_items.append({
                    "finding_id": finding.id,
                    "evidence_type": "CSAF Advisory",
                    "source": f"CSAF Advisory {advisory['csaf_id']}",
                    "text_snippet": (
                        f"CSAF advisory {advisory['csaf_id']} for {cve_id}: "
                        f"{advisory['description']}"
                    ),
                    "url_or_ref": f"CSAF advisory with ID {advisory['csaf_id']}"
                })

    return new_evidence_items, existing_evidence_items

