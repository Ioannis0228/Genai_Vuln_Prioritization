from pyvulnerabilitylookup import PyVulnerabilityLookup
client = PyVulnerabilityLookup()

def fetch_vulnerability_links(cve_id: str) -> dict:

    extracted_links = []

    try:

        result = client.get_vulnerability(f"{cve_id}?with_linked=true")

        cna = result.get("containers", {}).get("cna", {})
        adp_list = result.get("containers", {}).get("adp", [])
        linked_data = result.get("vulnerability-lookup:linked", {})


        references = cna.get("references", [])
        linked_urls = [ref.get("url", "") for ref in references if ref.get("url", "")]
        extracted_links.append({
            "data_type": "references",
            "source_provider": f"CNA ({cna.get('providerMetadata', {}).get('shortName', 'unknown')})",
            "url": linked_urls
        })
            
        for problem_type in cna.get("problemTypes", []):
            for desc in problem_type.get("descriptions", []):
                cwe_id = desc.get("cweId", "")
                if cwe_id:
                    extracted_links.append({
                            "data_type": "CWE",
                            "source_provider": f"CNA ({cna.get('providerMetadata', {}).get('shortName', 'unknown')})",
                            "entity_id": cwe_id,
                        })

        for adp in adp_list:
            provider_name = adp.get("providerMetadata", {}).get("shortName", "adp").upper()
            references = cna.get("references", [])
            linked_urls = [ref.get("url", "") for ref in references if ref.get("url", "")]
            extracted_links.append({
                "data_type": "references",
                "source_provider": provider_name,
                "url": linked_urls
            })

            for problemtype in adp.get("problemTypes", []):
                for desc in problemtype.get("descriptions", []):
                    cwe_id = desc.get("cweId", "")
                    if cwe_id:
                        extracted_links.append({
                            "data_type": "CWE",
                            "source_provider": provider_name,
                            "entity_id": cwe_id,
                        })
                

        for platform, payload in linked_data.items():
            if not isinstance(payload, list):
                continue
            
            for advisory in payload:
                advisory_id = (
                    advisory[1].get("id") or 
                    advisory[1].get("reference") or 
                    advisory[1].get("document", {}).get("tracking", {}).get("id")
                )
            
                advisory_urls = []
                
                if "references" in advisory[1].get("document", {}):
                    for ref in advisory[1]["document"]["references"]:
                        advisory_urls.append(ref["url"])
                        
                elif "references" in advisory[1]:
                    if isinstance(advisory[1]["references"], list):
                        for ref in advisory[1]["references"]:
                            advisory_urls.append(ref["url"])
                    elif isinstance(advisory[1]["references"], dict):
                        for url in advisory[1]["references"]["data"]:
                            advisory_urls.append(url["url"])

                if not advisory_id:
                    advisory_id = f"{platform.upper()}-DATA"

                extracted_links.append({
                    "data_type": "linked_advisory",
                    "source_provider": platform,
                    "entity_id": advisory_id,
                    "url": advisory_urls if advisory_urls else None
                })


        return {
            "cve_id": cve_id,
            "links": extracted_links
        }

    except Exception as e:

        return {
            "cve_id": cve_id,
            "error": str(e),
            "links": []
        }
