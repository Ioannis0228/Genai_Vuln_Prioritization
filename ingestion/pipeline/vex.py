import json

def parse_vex(input_file: str):
    
    with open(input_file, 'r', encoding='utf-8') as f:
        json_data = json.load(f)

    document = {
        "document_id": json_data.get('@id', ''),
        "author": json_data.get('author', ''),
        "timestamp": json_data.get('timestamp'),
        "version": json_data.get('version'),
        "statements": []
    }

    for statement in json_data.get('statements', []):
        parsed_statement = {
            "status": statement.get('status', ''),
            "justification": statement.get('justification', ''),
            "vulnerability": statement.get("vulnerability", {}).get("name").upper(),
            "products": [
                c.get("@id") if isinstance(c, dict) else c
                for c in statement.get("products", [])
            ],
            "subcomponents": [
                c.get("@id") if isinstance(c, dict) else c
                for product in statement.get("products", [])
                for c in product.get("subcomponents", []) 
            ]
        }

        document['statements'].append(parsed_statement)

    return document