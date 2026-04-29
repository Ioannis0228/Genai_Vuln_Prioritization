from database import SessionLocal, Vulnerabilities
from sqlalchemy import select

def get_CVEs_id()-> list[str]:
    with SessionLocal() as session:
        return session.execute(select(Vulnerabilities.cve_id)).scalars().all()
         
def check_existence(table, column, value = None)-> bool:
    if value is None:
        with SessionLocal() as session:
            return session.execute(select(table)).first() is not None
    else:
        with SessionLocal() as session:
            return session.execute(select(table).where(column == value)).first() is not None            
