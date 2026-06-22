"""SBOM parsing and normalization helpers.

This module converts CycloneDX SBOM JSON into normalized component records suitable for database insertion.
It uses the CycloneDX library to parse and validate SBOM structure.
"""

import json
from cyclonedx.model.bom import Bom

def parse_sbom(input_file: str) -> Bom:
    """Load a CycloneDX SBOM from JSON and convert it into a Bom object.
    
    Args:
        input_file (str): Path to the CycloneDX JSON SBOM file.
    
    Returns:
        Bom: Parsed SBOM object with metadata, components, and dependencies.
    """
    
    with open(input_file,'r', encoding='utf-8') as f:
        json_data = json.load(f)

    # Parse the JSON into a validated CycloneDX Bom object
    sbom = Bom.from_json(json_data)

    return sbom


def normalize_component(c) -> dict:
    """Convert a CycloneDX component into a database-friendly payload.
    
    Args:
        c: CycloneDX Component object.
    
    Returns:
        dict: Normalized component record with keys: type, bom_ref, name, version, 
              description, purl, cpe. All None values are preserved for optional fields.
    """
    
    return {
        "type": str(c.type),
        "bom_ref": str(c.bom_ref) if c.bom_ref else None,
        "name": c.name,
        "version": c.version or None,
        "description": c.description,
        "purl": str(c.purl) if c.purl else None,
        "cpe": str(c.cpe) if c.cpe else None,
    }