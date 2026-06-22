"""Service layer for ingesting VEX documents and their statements."""

from database import save_VEX_document, save_VEX_statements, check_existence, VEXdocuments
from ingestion import parse_vex


def process_vex(input_file: str):
    """Parse a VEX document and persist both its header and statements."""

    print("Parsing VEX document...")
    
    vex_document = parse_vex(input_file)
    if(check_existence(VEXdocuments, VEXdocuments.document_id, vex_document["document_id"])):
        print(f"VEX document with ID {vex_document['document_id']} already exists.")
        return

    vex_statements = vex_document.pop('statements', [])

    document_id = save_VEX_document(vex_document)
    save_VEX_statements(document_id, vex_statements)