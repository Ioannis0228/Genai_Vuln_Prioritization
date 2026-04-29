from .base import Base
from .session import SessionLocal, create_tables
from .models_db import Components, Vulnerabilities, KEVsnapshot, EPSSsnapshot, VEX, CSAFadvisories, Evidence, component_vulnerability, component_dependency, csaf_vulnerability
from .db_writer import save_components, save_CVEs, save_KEV_snapshot, save_EPSS_snapshot, save_CSAF_advisory, save_CVE_CSAF_mapping#, save_vex  
from .queries import get_CVEs_id, check_existence