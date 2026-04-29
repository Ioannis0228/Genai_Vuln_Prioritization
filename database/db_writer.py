from database import SessionLocal, Components, Vulnerabilities, KEVsnapshot, EPSSsnapshot, CSAFadvisories, component_dependency, component_vulnerability, csaf_vulnerability
from sqlalchemy.dialects.postgresql import insert


def save_components(normalized_components, dependencies=None):
    with SessionLocal() as session:

        # 1. Insert components
        stmt = insert(Components).values(normalized_components)
        stmt = stmt.on_conflict_do_nothing(
            index_elements=["purl"]
        )
        session.execute(stmt)
        session.commit()

        if not dependencies:
            return  # NO DEPENDENCIES TO PROCESS

        # 2. Collect all bom_refs from dependencies
        refs = set()
        for dep in dependencies:
            if not dep.ref:
                continue

            refs.add(str(dep.ref))

            for child in dep.dependencies or []:
                if child.ref:
                    refs.add(str(child.ref))

        # 3. Fetch matching components using bom_ref
        db_components = session.query(Components).filter(
            Components.bom_ref.in_(refs)
        ).all()

        # Map: bom_ref -> id
        comp_map = {c.bom_ref: c.id for c in db_components}

        # 4. Build dependency edges
        edges = []

        for dep in dependencies:
            parent_id = comp_map.get(str(dep.ref))
            if not parent_id:
                continue

            for child in dep.dependencies or []:
                child_ref = str(child.ref)
                if not child_ref:
                    continue

                child_id = comp_map.get(child_ref)
                if child_id:
                    edges.append({
                        "parent_id": parent_id,
                        "child_id": child_id
                    })

        # 5. Insert into association table
        if edges:
            stmt = insert(component_dependency).values(edges)
            stmt = stmt.on_conflict_do_nothing(
                index_elements=["parent_id", "child_id"]
            )
            session.execute(stmt)

        session.commit()


def save_CVEs(component_cve):
    with SessionLocal() as session:

        # 1 Build mapping: purl -> Component.id
        purls = {item["purl"] for item in component_cve}
        db_components = session.query(Components).filter(Components.purl.in_(purls)).all()
        comp_map = {c.purl: c.id for c in db_components}

        # 2 Prepare vulnerabilities list for insert
        vulnerabilities = [
            {k: v for k, v in item.items() if k != "purl"}  # remove purl
            for item in component_cve
        ]

        if vulnerabilities:
            stmt = insert(Vulnerabilities).values(vulnerabilities)
            stmt = stmt.on_conflict_do_nothing(index_elements=["cve_id"])
            session.execute(stmt)

        cve_ids = {item["cve_id"] for item in component_cve}

        vulns = session.query(Vulnerabilities).filter(
            Vulnerabilities.cve_id.in_(cve_ids)
        ).all()

        # Map: cve_id → DB id
        vuln_map = {v.cve_id: v.id for v in vulns}

        # 3 Prepare component vulnerability pairs for insert
        pairs = []

        for item in component_cve:
            comp_id = comp_map.get(item["purl"])
            vuln_id = vuln_map.get(item["cve_id"])

            if comp_id and vuln_id:
                pairs.append({
                    "component_id": comp_id,
                    "vulnerability_id": vuln_id
                })

        if pairs:
            stmt = insert(component_vulnerability).values(pairs)
            stmt = stmt.on_conflict_do_nothing(
                index_elements=["component_id", "vulnerability_id"]
            )
            session.execute(stmt)

        session.commit()

def save_KEV_snapshot(kev_data):
    with SessionLocal() as session:
        stmt = insert(KEVsnapshot).values(kev_data)
        stmt = stmt.on_conflict_do_nothing(index_elements=["cve_id"])
        session.execute(stmt)
        session.commit()

def save_EPSS_snapshot(epss_data):
    with SessionLocal() as session:
        stmt = insert(EPSSsnapshot).values(epss_data)
        stmt = stmt.on_conflict_do_nothing(index_elements=["cve_id"])
        session.execute(stmt)
        session.commit()

    
def save_CSAF_advisory(csaf_data,csaf_id):
    with SessionLocal() as session:
        stmt = insert(CSAFadvisories).values(csaf_id=csaf_id, data=csaf_data, description="Red Hat CSAF advisory")
        stmt = stmt.on_conflict_do_nothing(index_elements=["csaf_id"])
        session.execute(stmt)
        session.commit()
    
def save_CVE_CSAF_mapping(csaf_vuln):
    with SessionLocal() as session:
        if not csaf_vuln:
            return

        # Get all unique CVEs and RHSA IDs
        cve_ids = {item["cve_id"] for item in csaf_vuln}
        csaf_ids = {item["csaf_id"] for item in csaf_vuln}

        # Bulk query vulnerabilities
        vulns = session.query(Vulnerabilities).filter(
            Vulnerabilities.cve_id.in_(cve_ids)
        ).all()

        # Bulk query advisories
        advisories = session.query(CSAFadvisories).filter(
            CSAFadvisories.csaf_id.in_(csaf_ids)
        ).all()

        # Create maps
        vuln_map = {
            v.cve_id: v.id
            for v in vulns
        }

        csaf_map = {
            a.csaf_id: a.id
            for a in advisories
        }

        # Prepare insert pairs
        pairs = []

        for item in csaf_vuln:
            vuln_id = vuln_map.get(item["cve_id"])
            csaf_id = csaf_map.get(item["csaf_id"])

            if vuln_id and csaf_id:
                pairs.append({
                    "vulnerability_id": vuln_id,
                    "csaf_id": csaf_id
                })

        # Bulk insert
        if pairs:
            stmt = insert(csaf_vulnerability).values(pairs)

            stmt = stmt.on_conflict_do_nothing(
                index_elements=[
                    "vulnerability_id",
                    "csaf_id"
                ]
            )

            session.execute(stmt)
            session.commit()