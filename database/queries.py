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

def get_rows_by_column_in(session, tables, filter_column, filter_values, selected_columns=None):

    if not filter_values:
        return []

    if selected_columns is None:
        query = select(tables)
    else:
        query = select(*selected_columns)

    query = query.where(
        filter_column.in_(filter_values)
    )

    return session.execute(query).all()

def execute_select(session, selected_columns, where_conditions=None, joins=None):
    query = select(*selected_columns)

    if joins:
        for join_target, join_condition in joins:
            query = query.join(join_target, join_condition)

    if where_conditions:
        query = query.where(*where_conditions)

    return session.execute(query).all()