from .models_db import *
from .session import SessionLocal
from sqlalchemy.dialects.postgresql import insert


def save_sbom(sbom):
    sbom_dict = {
        "sbom_version": str(sbom.version),
        "bom_ref": str(sbom.metadata.component.bom_ref) if sbom.metadata.component.bom_ref else None,
        "timestamp": sbom.metadata.timestamp,
        "serial_number": str(sbom.serial_number),
        "product_name": sbom.metadata.component.name,
        "product_version": str(sbom.metadata.component.version),
        "description": str(sbom.metadata.component.description) if sbom.metadata.component.description else None
    }

    with SessionLocal() as session:
        stmt = insert(SBOM).values(sbom_dict).returning(SBOM.id)
        stmt = stmt.on_conflict_do_nothing(
            index_elements=["serial_number"]        
        )
        result = session.execute(stmt)
        inserted_id = result.scalar()

        if inserted_id is not None:
            session.commit()
            return inserted_id

        # already exists → fetch existing ID
        existing_id = session.query(SBOM.id).filter(
            SBOM.serial_number == sbom_dict["serial_number"]
        ).scalar()

        return existing_id


def save_components(sbom_id, normalized_components, dependencies=None):
    with SessionLocal() as session:

        # 1. Insert components
        stmt = insert(Components).values(normalized_components)
        stmt = stmt.on_conflict_do_nothing(
            index_elements=["purl"]
        )
        session.execute(stmt)
        session.commit()

        # 2. Fetch all components we care about
        purls = [
            comp["purl"]
            for comp in normalized_components
            if comp.get("purl")
        ]

        db_components = session.query(Components).filter(
            Components.purl.in_(purls)
        ).all()

        # Map for later use
        comp_map = {
            c.purl: {
                "id": c.id,
                "bom_ref": c.bom_ref
            }
            for c in db_components
        }

        # 3. Insert SBOM <-> Component associations

        sbom_links = []

        for comp in normalized_components:
            purl = comp.get("purl")
            if not purl:
                continue

            db_comp = comp_map.get(purl)
            if not db_comp:
                continue

            sbom_links.append({
                "sbom_id": sbom_id,
                "component_id": db_comp["id"]
            })

        if sbom_links:
            stmt = insert(sbom_component).values(sbom_links)
            stmt = stmt.on_conflict_do_nothing(
                index_elements=["sbom_id", "component_id"]
            )
            session.execute(stmt)

        session.commit()


        if not dependencies:
            return  # NO DEPENDENCIES TO PROCESS

        # 4. Collect all bom_refs from dependencies
        refs = set()
        for dep in dependencies:
            if not dep.ref:
                continue

            refs.add(str(dep.ref))

            for child in dep.dependencies or []:
                if child.ref:
                    refs.add(str(child.ref))

        # 5. Fetch matching components using bom_ref
        db_components = session.query(Components).filter(
            Components.bom_ref.in_(refs)
        ).all()

        # Map: bom_ref -> id
        comp_map = {c.bom_ref: c.id for c in db_components}

        # 6. Build dependency edges
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
                        "child_id": child_id,
                        "sbom_id": sbom_id
                    })

        # 7. Insert into association table
        if edges:
            stmt = insert(component_dependency).values(edges)
            stmt = stmt.on_conflict_do_nothing(
                index_elements=["parent_id", "child_id", "sbom_id"]
            )
            session.execute(stmt)

        session.commit()


def save_CVEs(sbom_id, component_cve):
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
            stmt = stmt.on_conflict_do_nothing(index_elements=["cve_id"]
                ).returning(Vulnerabilities.cve_id,
                            Vulnerabilities.cvss_score, 
                            Vulnerabilities.cvss_version,
                            Vulnerabilities.cvss_source)

            inserted_row = session.execute(stmt).fetchall()

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
                    "sbom_id": sbom_id,
                    "component_id": comp_id,
                    "vulnerability_id": vuln_id
                })

        if pairs:
            stmt = insert(Finding).values(pairs)
            stmt = stmt.on_conflict_do_nothing(
                index_elements=["sbom_id", "component_id", "vulnerability_id"]
            )
            session.execute(stmt)

        evidence_items = []
        for item in inserted_row:
            if item[0] and item[1]:  # cve_id is at index 0
                evidence_items.append({
                    "evidence_type": "CVSS score",
                    "source": item[3],
                    "cve_id": item[0],
                    "text_snippet": f"CVSS {item[2]}: {item[1]} from {item[3]}",
                    "url_or_ref": f"https://nvd.nist.gov/vuln/detail/{item[0]}"
                })
                
        if evidence_items:
            stmt = insert(Evidence).values(evidence_items)
            session.execute(stmt)

        session.commit()

def save_KEV_snapshot(kev_data):
    with SessionLocal() as session:
        stmt = insert(KEVsnapshot).values(kev_data)
        stmt = stmt.on_conflict_do_nothing(index_elements=["cve_id","created_on"]).returning(KEVsnapshot.cve_id, KEVsnapshot.catalog_added_date)
        inserted_rows = session.execute(stmt).fetchall()


        evidence_items = []
        for item in inserted_rows:
            if item[0]:
                evidence_items.append({
                    "evidence_type": "KEV",
                    "source": "CISA KEV catalog",
                    "cve_id": item[0],
                    "text_snippet": f"Added to KEV catalog on {item[1]}",
                    "url_or_ref": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                })

        if evidence_items:
            stmt = insert(Evidence).values(evidence_items)
            session.execute(stmt)

        session.commit()

def save_EPSS_snapshot(epss_data):
    with SessionLocal() as session:
        stmt = insert(EPSSsnapshot).values(epss_data)
        stmt = stmt.on_conflict_do_nothing(index_elements=["cve_id", "score_date"]).returning(EPSSsnapshot.cve_id, EPSSsnapshot.epss_score, EPSSsnapshot.score_date)
        inserted_row = session.execute(stmt).fetchall()

        evidence_items = []
        for item in inserted_row:
            if item[0] and item[1]:  # cve_id is at index 0
                evidence_items.append({
                    "evidence_type": "EPSS",
                    "source": "First.org EPSS API",
                    "cve_id": item[0],
                    "text_snippet": f"EPSS score: {item[1]} for {item[0]} on {item[2]}",
                    "url_or_ref": f"https://api.first.org/data/v1/epss?cve={item[0]}"
                })
        
        if evidence_items:
            stmt = insert(Evidence).values(evidence_items)
            session.execute(stmt)

        session.commit()

    
def save_CSAF_advisory(cve_id, csaf_data,csaf_id):
    with SessionLocal() as session:
        stmt = insert(CSAFadvisories).values(csaf_id=csaf_id, data=csaf_data, description="Red Hat CSAF advisory")
        stmt = stmt.on_conflict_do_nothing(index_elements=["csaf_id"]).returning(CSAFadvisories.csaf_id)
        inserted_row = session.execute(stmt).fetchall()

        evidence_items = []
        for item in inserted_row:
            if item[0]:  # csaf_id is at index 0
                evidence_items.append({
                    "evidence_type": "CSAF Advisory",
                    "source": "Red Hat CSAF Advisory API",
                    "cve_id": cve_id,
                    "text_snippet": f"Red Hat CSAF advisory with ID {item[0]} for {cve_id}.",
                    "url_or_ref": f"https://access.redhat.com/hydra/rest/securitydata/csaf/{item[0]}.json",
                })

        if evidence_items:
            stmt = insert(Evidence).values(evidence_items)
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


def save_finding_evidence_links(CVEs_id):
    with SessionLocal() as session:
        results = (
            session.query(Finding, Evidence)
            .join(Vulnerabilities, Finding.vulnerability_id == Vulnerabilities.id)
            .join(Evidence, Vulnerabilities.cve_id == Evidence.cve_id)
            .filter(Evidence.cve_id.in_(CVEs_id))
            .all()
        )

        for finding, evidence in results:
            if evidence not in finding.evidence_items:
                finding.evidence_items.append(evidence)

        session.commit()


def save_VEX_document(vex_data):
    with SessionLocal() as session:
        stmt = insert(VEXdocuments).values(
            document_id=vex_data["document_id"],
            author=vex_data["author"],
            timestamp=vex_data["timestamp"],
            version=vex_data["version"]
        ).returning(VEXdocuments.id)

        stmt = stmt.on_conflict_do_nothing(index_elements=["document_id"])
        result = session.execute(stmt)
        inserted_id = result.scalar()

        if inserted_id is not None:
            session.commit()
            return inserted_id

        existing_id = session.query(VEXdocuments.id).filter(
            VEXdocuments.document_id == vex_data["document_id"]
        ).scalar()

        return existing_id
    
def save_VEX_statements(document_id, statements):
    with SessionLocal() as session:

        for statement in statements:

            if not statement.get("subcomponents"): 
                components_ids = session.query(Components.id).filter(
                    Components.purl.in_(statement.get("products", []))
                ).all()
                sbom_id = None

            else:
                components_ids = session.query(Components.id).filter(
                    Components.purl.in_(statement.get("subcomponents", []))
                ).all()

                sbom_id = session.query(SBOM.id).filter(
                    SBOM.bom_ref.in_(statement.get("products", []))
                ).scalar()


            

            vulnerability_id = session.query(Vulnerabilities.id).filter(
                Vulnerabilities.cve_id == statement.get("vulnerability", "")
            ).scalar()

            new_statement = VEXstatements(
                document_id=document_id,
                sbom_id = sbom_id,
                status=statement.get("status", ""),
                justification=statement.get("justification", ""),
                vulnerability=vulnerability_id,
            )

            session.add(new_statement)
            session.flush()  
            
            for (component_id,) in components_ids:
                session.execute(
                    vex_statement_component.insert().values(
                        statement_id=new_statement.id,
                        component_id=component_id
                    )
                )

            evidence_items = []
            for component_id in components_ids:
                evidence_items.append({
                    "evidence_type": "VEX Statement",
                    "source": "VEX document",
                    "cve_id": statement.get("vulnerability", ""),
                    "text_snippet": f"VEX statement with status '{statement.get('status', '')}' and justification '{statement.get('justification', '')}' for component ID {component_id}.",
                    "url_or_ref": f"VEX document ID: {document_id}"
                })
                stmt = insert(Evidence).values(evidence_items)
            session.execute(stmt)

        session.commit()

def save_vuln_enrichment(enrichment_list):
    rows = [
        {
            "cve_id": data["cve_id"],
            "data_type": link.get("data_type", ""),
            "source_provider": link.get("source_provider", ""),
            "entity_id": link.get("entity_id", ""),
            "url": link.get("url")
        } for data in enrichment_list
        for link in data.get("links",[])
    ]

    with SessionLocal() as session:
        stmt = insert(VulnerabilityEnrichment).values(rows)
        session.execute(stmt)
        session.commit()