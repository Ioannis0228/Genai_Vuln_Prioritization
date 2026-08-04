"""Persistence helpers that write parsed SBOM, CVE, VEX, and intelligence data.

This module handles the upsert logic for all ingested data types, managing:
- SBOM records and their component relationships
- Vulnerability records and finding joins
- VEX documents and statements
- KEV and EPSS snapshots with evidence tracking
- CSAF advisory linkages
"""

from .models_db import *
from .session import SessionLocal
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy import update, select
from datetime import datetime, UTC


def save_sbom(sbom) -> int:
    """Insert a Software Bill of Materials (SBOM) record into the database.

    If a record with the same serial number already exists, the insertion is
    ignored, and the identifier of the existing record is retrieved and returned.

    Args:
        sbom: An SBOM object containing metadata, component details, and a serial number.

    Returns:
        int: The database identifier (ID) of the newly inserted or existing SBOM record.
    """

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

        # already exists, fetch existing ID
        existing_id = session.query(SBOM.id).filter(
            SBOM.serial_number == sbom_dict["serial_number"]
        ).scalar()

        return existing_id


def save_components(sbom_id: int, normalized_components: list, dependencies: list = None) -> None:
    """Persist normalized components, link them to an SBOM, and build dependency edges.

    This function processes the ingredients of an SBOM using a 4-step pipeline:
    1. Bulk upserts components to the global `Components` table using PURLs 
       to handle duplicates.
    2. Maps the components to the specific SBOM instance via the `sbom_component` 
       association table (recording local `bom_ref` contexts).
    3. Scans and resolves graph nodes (`bom_ref` strings) to their database IDs.
    4. Constructs and bulk-inserts directional dependency edges into the 
       `component_dependency` table.

    Args:
        sbom_id (int): The database identifier of the target SBOM record.
        normalized_components (list[dict]): A list of dicts representing parsed components.
            Each dictionary must contain 'purl' and 'bom_ref' keys.
        dependencies (list[Object], optional): A list of dependency objects (e.g., CycloneDX 
            Dependency structures) containing a `.ref` attribute and an optional 
            list of sub-dependencies under `.dependencies`. Defaults to None.

    Returns:
        None
    """

    purls = []
    components_rows = []
    for comp in normalized_components:
        if comp.get("purl"):
            purls.append(comp["purl"])
            components_rows.append({k: v for k, v in comp.items() if k != "bom_ref"})

    with SessionLocal() as session:

        # 1. Insert components
        stmt = insert(Components).values(components_rows)
        stmt = stmt.on_conflict_do_nothing(
            index_elements=["purl"]
        )
        session.execute(stmt)
        session.commit()
        
        # 2. Fetch DB IDs for all components
        db_components = session.query(Components).filter(
            Components.purl.in_(purls)
        ).all()

        # Map for later use
        comp_map = {
            c.purl: {"id": c.id}
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
                "component_id": db_comp["id"],
                "bom_ref": comp["bom_ref"],
            })

        if sbom_links:
            stmt = insert(sbom_component).values(sbom_links)
            stmt = stmt.on_conflict_do_nothing(
                index_elements=["sbom_id", "bom_ref"]
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
        db_components = session.query(sbom_component).filter(
            sbom_component.c.sbom_id == sbom_id,
            sbom_component.c.bom_ref.in_(refs)
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


def save_CVEs(sbom_id: int, component_cve: list) -> None:
    """Persist vulnerabilities, map them to components via findings, and log CVSS metadata.

    This function performs a 4-step relational persistence pipeline:
    1. Resolves input Package URLs (PURLs) to existing global database `Components` IDs.
    2. Bulk upserts distinct CVE records into the `Vulnerabilities` table.
    3. Links identified vulnerabilities to specific SBOM components inside the 
       `Finding` junction table, ignoring duplicate combinations.
    4. Records auditing metadata into the `Evidence` table for newly introduced 
       vulnerability metrics (CVSS score, source, version).

    Args:
        sbom_id (int): The primary key of the parent SBOM file context.
        component_cve (list[dict]): A list of dicts representing parsed scanner definitions.
            Each dict requires the following keys: 'purl', 'cve_id', 'description', 
            'cvss_score', 'cvss_version', and 'cvss_source'.

    Returns:
        None
    """

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

        inserted_row = []
        if vulnerabilities:
            stmt = insert(Vulnerabilities).values(vulnerabilities)
            stmt = stmt.on_conflict_do_nothing(index_elements=["cve_id"]
                ).returning(Vulnerabilities.cve_id,
                            Vulnerabilities.cvss_score, 
                            Vulnerabilities.cvss_version,
                            Vulnerabilities.cvss_source,
                            Vulnerabilities.id,
                            )

            inserted_row = session.execute(stmt).fetchall()

        cve_ids = {item["cve_id"] for item in component_cve}

        # Map: cve_id → DB id
        vuln_map = dict(session.execute(
            select(Vulnerabilities.cve_id, Vulnerabilities.id)
            .where(Vulnerabilities.cve_id.in_(cve_ids))
            ).tuples().all()
        )

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
                    "source_record_id": item[4],
                    "text_snippet": f"CVSS {item[2]}: {item[1]} from {item[3]}",
                    "url_or_ref": f"https://nvd.nist.gov/vuln/detail/{item[0]}"
                })
                
        if evidence_items:
            stmt = insert(Evidence).values(evidence_items)
            session.execute(stmt)

        session.commit()

def save_KEV_snapshot(kev_data: list[dict]) -> None:
    """Persist CISA Known Exploited Vulnerabilities (KEV) data and generate audit evidence.

    This function bulk-inserts incoming KEV records into the `KEVsnapshot` table.
    To prevent data duplication on recurring catalog scans, it ignores records matching 
    an existing combination of 'cve_id' and 'created_on'. For any newly inserted 
    vulnerabilities, a corresponding entry is created in the global `Evidence` 
    table referencing the CISA KEV catalog feed source.

    Args:
        kev_data (list[dict]): A list of dictionaries, where each dict represents a KEV 
            catalog entry containing keys like 'cve_id', 'created_on', and 'catalog_added_date'.

    Returns:
        None
    """

    if not kev_data:
        return  # No data to process

    inserted_rows = []
    with SessionLocal() as session:
        stmt = insert(KEVsnapshot).values(kev_data)
        stmt = stmt.on_conflict_do_nothing(index_elements=["cve_id","created_on"]
                                           ).returning(KEVsnapshot.cve_id, 
                                                       KEVsnapshot.catalog_added_date, 
                                                       KEVsnapshot.id)
        inserted_rows = session.execute(stmt).fetchall()


        evidence_items = []
        for item in inserted_rows:
            if item[0]:
                evidence_items.append({
                    "evidence_type": "KEV",
                    "source": "CISA KEV catalog",
                    "cve_id": item[0],
                    "source_record_id": item[2],
                    "text_snippet": f"Added to KEV catalog on {item[1]}",
                    "url_or_ref": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                })

        if evidence_items:
            stmt = insert(Evidence).values(evidence_items)
            session.execute(stmt)

        session.commit()

def save_EPSS_snapshot(epss_data: list[dict]) -> None:
    """Persist Exploit Prediction Scoring System (EPSS) data and generate matching evidence entries.

    This function updates the database by bulk-inserting daily EPSS snapshot records 
    into the `EPSSsnapshot` table. To manage repetitive data ingestion from daily feeds,
    it ignores entries matching an existing combination of 'cve_id' and 'score_date'.
    For newly logged vulnerabilities, it generates a corresponding entry in the global
    `Evidence` table capturing the exact score and score date.

    Args:
        epss_data (list[dict]): A list of dictionaries representing daily EPSS metrics.
            Each dictionary must include keys like 'cve_id', 'epss_score', and 'score_date'.

    Returns:
        None
    """

    with SessionLocal() as session:
        stmt = insert(EPSSsnapshot).values(epss_data)
        stmt = stmt.on_conflict_do_nothing(index_elements=["cve_id", "score_date"]
                                           ).returning(EPSSsnapshot.cve_id, 
                                                       EPSSsnapshot.epss_score, 
                                                       EPSSsnapshot.score_date, 
                                                       EPSSsnapshot.id)
        inserted_row = session.execute(stmt).fetchall()

        evidence_items = []
        for item in inserted_row:
            if item[0] and item[1]:  # cve_id is at index 0
                evidence_items.append({
                    "evidence_type": "EPSS",
                    "source": "First.org EPSS API",
                    "cve_id": item[0],
                    "source_record_id": item[3],
                    "text_snippet": f"EPSS score: {item[1]} for {item[0]} on {item[2]}",
                    "url_or_ref": f"https://api.first.org/data/v1/epss?cve={item[0]}"
                })
        
        if evidence_items:
            stmt = insert(Evidence).values(evidence_items)
            session.execute(stmt)

        session.commit()

    
def save_CSAF_advisory(cve_id: str, csaf_data: dict | str, csaf_id: str):
    """Persist a Common Security Advisory Framework (CSAF) advisory and log audit evidence.

    This function attempts to bulk-insert a parsed vendor security advisory into the 
    `CSAFadvisories` database table. If an advisory with the identical 'csaf_id' 
    already exists, the insert statement will execute without error but make no changes.

    Args:
        cve_id (str): The unique identifier of the security flaw (e.g., 'CVE-2026-1234') 
            linked to this vendor warning.
        csaf_data (dict | str): The raw or JSON-structured content payload representing 
            the body of the security advisory document.
        csaf_id (str): The unique tracking ID issued by the advisory authority 
            (e.g., 'RHSA-2026:5678').

    Returns:
        None
    """

    with SessionLocal() as session:
        stmt = insert(CSAFadvisories).values(csaf_id=csaf_id, data=csaf_data, description="Red Hat CSAF advisory")
        stmt = stmt.on_conflict_do_nothing(index_elements=["csaf_id"]).returning(CSAFadvisories.csaf_id)
        session.execute(stmt)
        session.commit()
    
def save_CVE_CSAF_mapping(csaf_vuln: list[dict]) -> None:
    """Populate the many-to-many junction table linking CVEs to CSAF advisories.

    This function resolves relationship mappings using a 3-step pipeline:
    1. Collects unique vulnerability and advisory keys from the input data feed 
       to perform highly optimized bulk database lookups.
    2. Builds in-memory cross-reference dictionaries mapping string IDs (`cve_id`, 
       `csaf_id`) directly to their primary database integer IDs.
    3. Bundles verified relationship pairs and bulk-inserts them into the 
       `csaf_vulnerability` association table, ignoring rows that have 
       already been linked on previous executions.

    - Also creates corresponding entries in the `Evidence` table for each new CVE-CSAF mapping,
    capturing the advisory source and a reference URL.

    Args:
        csaf_vuln (list[dict]): A list of dictionaries representing mapping records.
            Each dictionary must contain 'cve_id' (str) and 'csaf_id' (str) keys.

    Returns:
        None
    """

    with SessionLocal() as session:
        if not csaf_vuln:
            return

        # Get all unique CVEs and RHSA IDs
        cve_ids = {item["cve_id"] for item in csaf_vuln}
        csaf_ids = {item["csaf_id"] for item in csaf_vuln}

        # Create maps
        vuln_map = dict(session.execute(
            select(Vulnerabilities.cve_id, Vulnerabilities.id)
            .where(Vulnerabilities.cve_id.in_(cve_ids))
            ).tuples().all()
        )

        csaf_map = dict(session.execute(
            select(CSAFadvisories.csaf_id, CSAFadvisories.id)
            .where(CSAFadvisories.csaf_id.in_(csaf_ids))
            ).tuples().all()
        )

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

        evidence_items = []
        for item in csaf_vuln:
            evidence_items.append({
                "evidence_type": "CSAF Advisory",
                "source": "Red Hat CSAF Advisory API",
                "cve_id": item["cve_id"],
                "source_record_id": csaf_map.get(item["csaf_id"]),
                "text_snippet": f"Red Hat CSAF advisory with ID {item['csaf_id']} for {item['cve_id']}.",
                "url_or_ref": f"https://access.redhat.com/hydra/rest/securitydata/csaf/{item['csaf_id']}.json",
            })

        if evidence_items:
            stmt = insert(Evidence).values(evidence_items).on_conflict_do_nothing()
            session.execute(stmt)

        session.commit()


def save_finding_evidence_links(CVE_ids: set[str]) -> None:
    """Attach existing evidence rows to findings that reference the same CVEs.

    This function builds relationships in a many-to-many junction table by:
    1. Executing a relational join across `Finding`, `Vulnerabilities`, and `Evidence` 
       tables to find matching data points scoped to a target set of CVE identifiers.
    2. Iterating through the joined results to check if the specific `Evidence` record 
       is already linked to the `Finding` instance via the ORM relationship collection.
    3. Appending unlinked `Evidence` objects directly into the `finding.evidence_items` 
       relationship collection and committing the changes.

    Args:
        CVE_ids (set[str]): A collection of unique CVE alphanumeric string identifiers 
            (e.g., ['CVE-2026-1234', 'CVE-2026-5678']) used to isolate the linking operation.

    Returns:
        None
    """

    with SessionLocal() as session:
        results = (
            session.query(Finding, Evidence)
            .join(Vulnerabilities, Finding.vulnerability_id == Vulnerabilities.id)
            .join(Evidence, Vulnerabilities.cve_id == Evidence.cve_id)
            .filter(Evidence.cve_id.in_(CVE_ids))
            .all()
        )

        for finding, evidence in results:
            if evidence not in finding.evidence_items:
                finding.evidence_items.append(evidence)

        session.commit()


def save_VEX_document(vex_data: dict) -> int:
    """Insert a Vulnerability Exploit Exchange (VEX) document header or return the existing ID.

    This function attempts to store the foundational metadata of a VEX advisory.
    If a document with the same 'document_id' has already been persisted, the 
    database ignore-constraint is triggered, and a fallback query retrieves the 
    existing record's primary key identifier.

    Args:
        vex_data (dict): A dictionary containing parsed VEX header metadata. 
            Must include 'document_id' (str), 'author' (str), 'timestamp' (datetime), 
            and 'version' (str) keys.

    Returns:
        int: The database primary key identifier (ID) of the new or existing VEX document.
    """

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
    
def save_VEX_statements(document_id: int, statements: list[dict]) -> None:
    """Persist VEX statements, establish component mappings, and create audit evidence.

    This function processes a collection of Vulnerability Exploit Exchange (VEX) 
    statements. For each statement, it applies conditional logic to resolve targets:
    - If 'subcomponents' are absent, it maps the vulnerability directly to the main 
      products matching the provided PURLs.
    - If 'subcomponents' are present, it links the vulnerability to those targeted 
      subcomponents, and maps the parent product to its corresponding `sbom_id` via `bom_ref`.

    Once foreign keys are evaluated, the individual VEX statement is recorded, its 
    many-to-many relationships are written to the `vex_statement_component` junction 
    table, and matching entries are generated in the global `Evidence` database.

    Args:
        document_id (int): Primary key identifier of the parent VEX header document.
        statements (list[dict]): A list of dictionaries parsed from a VEX JSON file, 
            containing keys such as 'vulnerability', 'status', 'justification', 
            'products', and optionally 'subcomponents'.

    Returns:
        None
    """

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
            for (component_id,) in components_ids:
                evidence_items.append({
                    "evidence_type": "VEX Statement",
                    "source": "VEX document",
                    "cve_id": statement.get("vulnerability", ""),
                    "source_record_id": new_statement.id,
                    "text_snippet": f"VEX statement with status '{statement.get('status', '')}' and justification '{statement.get('justification', '')}' for component ID {component_id}.",
                    "url_or_ref": f"VEX document ID: {document_id}"
                })
            
            if evidence_items:
                stmt = insert(Evidence).values(evidence_items)
                session.execute(stmt)

        session.commit()

def save_vuln_enrichment(enrichment_list: list[dict]) -> None:
    """Persist enrichment rows derived from Vulnerability Lookup.

    This function flattens a nested data structure into single database rows:
    1. It iterates through an input payload list where each entry holds a 'cve_id' 
       and an internal array of associated threat metadata references ('links').
    2. It transforms and normalizes these values into a single array of dictionary payloads.
    3. It performs a high-efficiency batch insertion into the `VulnerabilityEnrichment` 
       table inside a localized transaction.

    Args:
        enrichment_list (list[dict]): A list of dictionaries representing enrichment contexts.
            Each dictionary must contain a 'cve_id' (str) key and a 'links' (list[dict]) key
            containing target references (e.g., 'data_type', 'source_provider', 'url').

    Returns:
        None
    """

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

def save_fusion_results(risk_assessment):
    """Update existing finding rows with compiled risk fusion scores and rank justifications.

    This function processes final analytical metrics output by a risk scoring engine.
    It loops through evaluated assessments, normalizes the keys (including mapping the 
    space-separated 'why-ranked' string), and executes a bulk update on the `Finding` 
    table to store localized prioritization metrics and update timestamps.

    Args:
        risk_assessment (list[dict]): A list of processed risk assessment dicts. Each dict 
            must contain 'finding_id' (int), 'fusion_score' (float), 'priority' (str), 
            and 'why-ranked' (str) keys.

    Returns:
        None
    """

    rows = [{
            "id": item["finding_id"],
            "fusion_score": item["fusion_score"],
            "priority": item["priority"],
            "rank": item["rank"],
            "why_ranked": item["why-ranked"],
            "last_updated": datetime.now(UTC)
        } for item in risk_assessment
    ]

    with SessionLocal() as session: 
        if rows:
            session.execute(
                update(Finding),
                rows
            )
        session.commit()