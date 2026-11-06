from collections import defaultdict
from typing import List, Dict
from packageurl import PackageURL
import typer
from .schemas import Claim, GroundedExplanation, GroundedExplanationList, ClaimType

# GENERAL HELPERS
def get_component_details(component_purl: str) -> dict:
    """Extract component name and installed version from PURL."""

    try:
        package = PackageURL.from_string(component_purl)

        return {
            "name": package.name,
            "version": package.version or "Unknown",
            "purl": component_purl,
        }

    except Exception:
        return {
            "name": component_purl,
            "version": "Unknown",
            "purl": component_purl,
        }


def deduplicate_claims(claims: List[Claim]) -> List[Claim]:
    """
    Remove exact duplicate claims while preserving order.
    Claims with different evidence IDs remain separate.
    """

    unique = []
    seen = set()
    for claim in claims:
        key = (
            claim.summary,
            claim.claim_type,
            claim.value,
            claim.evidence_id,
        )

        if key not in seen:
            seen.add(key)
            unique.append(claim)

    return unique


def collect_claims(explanations: List[GroundedExplanation], claim_types: set, source: str = "all") -> List[Claim]:
    """
    Collect claims from multiple findings.

    source:
        why  -> why_prioritized_now
        next -> what_to_do_next
        all  -> both collections
    """

    claims = []
    for explanation in explanations:

        if source in ("why", "all"):
            claims.extend(
                claim
                for claim in explanation.why_prioritized_now
                if claim.claim_type in claim_types
            )

        if source in ("next", "all"):
            claims.extend(
                claim
                for claim in explanation.what_to_do_next
                if claim.claim_type in claim_types
            )

    return deduplicate_claims(claims)


def format_claims(claims: List[Claim], indent: int = 1) -> str:
    """Format claims while preserving evidence references."""

    if not claims:
        return ""

    prefix = "    " * indent
    output = []
    for claim in claims:

        line = f"{prefix}- {claim.summary}"

        if claim.evidence_id is not None:
            line += f" (Ref: EvID {claim.evidence_id})"

        line += f" [Type: {claim.claim_type.value}]"

        output.append(line)

        if claim.value:
            output.append(
                f"{prefix}    Value: {claim.value}"
            )

    return "\n".join(output)


def append_claim_section(output: List[str], title: str, claims: List[Claim]):
    """Append a section only when supporting claims exist."""

    if not claims:
        return

    output.append(
        typer.style(
            f"\n{title}",
            fg=typer.colors.CYAN,
            bold=True,
        )
    )

    output.append(format_claims(claims))


def append_missing_information(output: List[str], message: str):
    """Display missing information without inventing details."""

    output.append(
        typer.style(
            f"\n{message}",
            fg=typer.colors.YELLOW,
        )
    )

# GROUPING FUNCTIONS
def group_by_component(explanations: List[GroundedExplanation]) -> Dict[str, List[GroundedExplanation]]:
    """Group findings by component PURL."""

    groups = defaultdict(list)

    for explanation in explanations:
        groups[explanation.component_purl].append(explanation)

    return dict(groups)


def group_by_cve(explanations: List[GroundedExplanation]) -> Dict[str, List[GroundedExplanation]]:
    """Group findings by CVE."""

    groups = defaultdict(list)

    for explanation in explanations:
        groups[explanation.Vulnerability].append(explanation)

    return dict(groups)


# DEVELOPER NARRATIVE
def render_developer_narrative(item: GroundedExplanationList) -> str:
    """
    Developer view:

    Component
        -> Installed version
        -> CVE
            -> Vendor advisories
            -> Available remediation
            -> Mitigation

    Each action remains associated with its CVE.
    """

    output = []
    groups = group_by_component(item.explanations)

    for purl, explanations in groups.items():

        component = get_component_details(purl)
        output.append(
            typer.style(
                f"\n{'=' * 55}\n"
                f"Component: {component['name']}\n"
                f"{'=' * 55}",
                fg=typer.colors.MAGENTA,
                bold=True,
            )
        )

        output.append(f"Installed Version: {component['version']}")
        output.append(f"Component PURL: {component['purl']}")

        for explanation in explanations:

            output.append(
                typer.style(
                    f"\nVulnerability: {explanation.Vulnerability}",
                    fg=typer.colors.RED,
                    bold=True,
                )
            )

            output.append(f"Finding Rank: {explanation.rank}")

            # Vendor advisories for this CVE
            vendor_claims = collect_claims(
                [explanation],
                {
                    ClaimType.CSAF_Advisory,
                    ClaimType.Vendor_Advisory,
                },
                source="all",
            )

            append_claim_section(output, "Vendor Advisory Information", vendor_claims)

            # Remediation for this CVE
            remediation_claims = collect_claims(
                [explanation],
                {ClaimType.Remediation_Step},
                source="next",
            )

            append_claim_section(output, "Available Fixes and Remediation", remediation_claims)

            # Mitigation for this CVE
            mitigation_claims = collect_claims(
                [explanation],
                {ClaimType.Mitigation},
                source="next",
            )

            append_claim_section(output, "Mitigation and Workarounds", mitigation_claims)

            if not remediation_claims and not mitigation_claims:
                append_missing_information(
                    output,
                    "No actionable remediation or mitigation "
                    "information is available for this CVE "
                    "in the supplied evidence.",
                )

    return "\n".join(output)

# DEVOPS NARRATIVE
def render_devops_narrative(item: GroundedExplanationList) -> str:
    """
    DevOps view:

    CVE
        -> Affected components
        -> Applicability
        -> Vendor information
        -> Operational mitigation
        -> Available upgrade actions
    """

    output = []
    groups = group_by_cve(item.explanations)

    for cve, explanations in groups.items():

        output.append(
            typer.style(
                f"\n{'=' * 55}\n"
                f"Vulnerability: {cve}\n"
                f"{'=' * 55}",
                fg=typer.colors.MAGENTA,
                bold=True,
            )
        )

        ranks = sorted({
            explanation.rank
            for explanation in explanations
        })

        output.append(f"Finding Rank(s): {', '.join(map(str, ranks))}")

        # Affected components
        output.append(
            typer.style(
                "\nAffected Components",
                fg=typer.colors.CYAN,
                bold=True,
            )
        )

        for explanation in explanations:

            component = get_component_details(explanation.component_purl)

            output.append(
                f"  - {component['name']} "
                f"(Version: {component['version']}, "
                f"Rank: {explanation.rank})"
            )

        # Applicability and vendor information
        operational_claims = collect_claims(
            explanations,
            {
                ClaimType.VEX_Statement,
                ClaimType.Vendor_Advisory,
                ClaimType.CSAF_Advisory,
            },
            source="all",
        )

        append_claim_section(output, "Applicability and Vendor Information", operational_claims)

        # Operational mitigation
        mitigation_claims = collect_claims(
            explanations,
            {ClaimType.Mitigation},
            source="next",
        )

        append_claim_section(output, "Operational Mitigation", mitigation_claims)

        # Upgrade and remediation actions
        remediation_claims = collect_claims(
            explanations,
            {ClaimType.Remediation_Step},
            source="next",
        )

        append_claim_section(output, "Available Upgrade and Remediation Actions", remediation_claims)

        if not remediation_claims and not mitigation_claims:
            append_missing_information(
                output,
                "No explicit operational remediation or mitigation "
                "instructions are available in the supplied evidence.",
            )

    return "\n".join(output)


# SECURITY LEAD NARRATIVE
def render_security_lead_narrative(item: GroundedExplanationList) -> str:
    """
    Security Lead view:

    Security Overview
        -> Total findings
        -> Unique vulnerabilities
        -> Affected components
        -> KEV evidence
        -> Highest-priority rank

    Priority
        -> CVE
        -> Affected components
        -> Severity and exploitation risk
        -> Applicability
        -> Vendor context
        -> Risk reduction actions

    Each CVE appears only once, even when it affects
    multiple components with different finding ranks.
    """

    output = []
    append_security_overview(output, item)
    groups = group_by_cve(item.explanations)

    for cve, explanations in groups.items():

        # Lowest rank represents highest priority
        priority = explanations[0].rank

        output.append(
            typer.style(
                f"\n{'=' * 55}\n"
                f"Priority Rank: {priority}\n"
                f"Vulnerability: {cve}\n"
                f"{'=' * 55}",
                fg=typer.colors.YELLOW,
                bold=True,
            )
        )

        # Affected components and individual ranks
        output.append(
            typer.style(
                "\nAffected Components",
                fg=typer.colors.CYAN,
                bold=True,
            )
        )

        for explanation in explanations:

            component = get_component_details(explanation.component_purl)

            output.append(
                f"  - {component['name']} "
                f"(Version: {component['version']}, "
                f"Rank: {explanation.rank})"
            )

        # Severity and exploitation risk
        risk_claims = collect_claims(
            explanations,
            {
                ClaimType.CVSS,
                ClaimType.EPSS,
                ClaimType.KEV,
            },
            source="why",
        )

        append_claim_section(output, "Severity and Exploitation Risk", risk_claims)

        # Applicability
        applicability_claims = collect_claims(
            explanations,
            {ClaimType.VEX_Statement},
            source="all",
        )

        append_claim_section(output, "Vulnerability Applicability", applicability_claims)

        # Vendor context
        vendor_claims = collect_claims(
            explanations,
            {
                ClaimType.CSAF_Advisory,
                ClaimType.Vendor_Advisory,
                ClaimType.Other,
            },
            source="all",
        )

        append_claim_section(output, "Additional Security Context", vendor_claims)

        # Risk reduction
        action_claims = collect_claims(
            explanations,
            {
                ClaimType.Remediation_Step,
                ClaimType.Mitigation,
            },
            source="next",
        )

        append_claim_section(output, "Risk Reduction Actions", action_claims)

        if not action_claims:
            append_missing_information(
                output,
                "No evidence-backed remediation or mitigation "
                "actions are available in the supplied evidence.",
            )

    return "\n".join(output)

def append_security_overview(output: List[str], item: GroundedExplanationList):
    """
    Append a high-level security overview.

    Metrics are derived exclusively from supplied findings
    and their supporting evidence.
    """

    explanations = item.explanations

    if not explanations:
        output.append("No vulnerability findings available.")
        return

    unique_cves = {
        explanation.Vulnerability
        for explanation in explanations
    }

    unique_components = {
        explanation.component_purl
        for explanation in explanations
    }

    kev_cves = {
        explanation.Vulnerability
        for explanation in explanations
        if any(
            claim.claim_type == ClaimType.KEV
            for claim in explanation.why_prioritized_now
        )
    }

    output.append(typer.style(
            f"Unique Vulnerabilities: {len(unique_cves)}",
            fg=typer.colors.BRIGHT_RED,
            bold=True,
        )
    )
    output.append(typer.style(
            f"Affected Components: {len(unique_components)}",
            fg=typer.colors.MAGENTA,
            bold=True,
        )
    )
    kev_color = (typer.colors.RED if kev_cves else typer.colors.GREEN)

    output.append(typer.style(
            f"CVEs with KEV Evidence: {len(kev_cves)}",
            fg=kev_color,
            bold=True,
        )
    )

# MAIN PERSONA NARRATIVE FUNCTION
def render_persona_narratives(item: GroundedExplanationList, persona: str) -> str:
    """
    Entry point for all persona narratives.

    Supported personas:
        developer
        devops
        security_lead
    """

    persona = persona.lower().strip()

    narrative_functions = {
        "developer": render_developer_narrative,
        "devops": render_devops_narrative,
        "security_lead": render_security_lead_narrative,
    }

    if persona not in narrative_functions:
        raise ValueError(
            f"Unsupported persona: {persona}. "
            f"Expected one of: "
            f"{', '.join(narrative_functions.keys())}"
        )

    return narrative_functions[persona](item)