"""Common database query helpers used across services.

This module provides reusable query building and execution functions that abstract
away SQLAlchemy complexity for common patterns: filtering, joining, and snapshot retrieval.
"""

from database import SessionLocal, Vulnerabilities, Finding
from sqlalchemy import select

def get_CVE_ids(sbom_id: int)-> list[str]:
    """Return stored CVE identifier as a list of strings for a given SBOM ID.
    
    Returns:
        list: All unique CVE IDs for the specified SBOM ID currently in the Vulnerabilities table.
    """

    with SessionLocal() as session:
        return session.execute(select(Vulnerabilities.cve_id).distinct()
                               .select_from(Finding)
                               .join(Vulnerabilities, Finding.vulnerability_id == Vulnerabilities.id)
                               .where(Finding.sbom_id == sbom_id)
                               ).scalars().all()
         
def check_existence(table, column, value = None)-> bool:
    """Check whether a row exists, optionally constrained by a column value.
    
    Args:
        table: SQLAlchemy ORM table or model class to query.
        column: Column to filter on (ignored if value is None).
        value (optional): Value to match in the column. If None, checks if table has any rows.
    
    Returns:
        bool: True if any matching row exists, False otherwise.
    """

    if value is None:
        with SessionLocal() as session:
            return session.execute(select(table)).first() is not None
    else:
        with SessionLocal() as session:
            return session.execute(select(table).where(column == value)).first() is not None  

def get_rows_by_column_in(session, tables, filter_column, filter_values, selected_columns=None):
    """Fetch rows where a column matches any value from the provided iterable.
    
    Args:
        session: Active SQLAlchemy session.
        tables: Table(s) to query.
        filter_column: Column to filter on using IN operator.
        filter_values (list): Values to match (empty list returns empty result).
        selected_columns (optional): Specific columns to select. If None, selects all from tables.
    
    Returns:
        list: Query result rows matching the filter condition.
    """

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

def execute_select(session, selected_columns, where_conditions=None, joins=None, order_by=None, limit=None, options=None):
    """Execute a configurable SELECT query with optional joins and filters.
    
    Args:
        session: Active SQLAlchemy session.
        selected_columns: List of columns to select.
        where_conditions (optional): List of WHERE clause conditions to AND together.
        joins (optional): List of tuples (join_target, join_condition) to apply sequentially.
        order_by (optional): List of columns to order the results by.
        limit (optional): Maximum number of rows to return.
        options (optional): Additional options for the query.
    Returns:
        list: Query result rows.
    """
    query = select(*selected_columns)

    if joins:
        for join_target, join_condition in joins:
            query = query.join(join_target, join_condition)

    if where_conditions:
        query = query.where(*where_conditions)
    
    if order_by:
        query = query.order_by(*order_by)
    
    if limit:
        query = query.limit(limit)

    if options:
        query = query.options(*options)

    return session.execute(query).all()

def get_latest_snapshots(session, table, cve_ids, date_column, selected_columns, date=None)-> list:
    """Return the snapshot rows for the supplied CVEs from the latest available snapshot date.

    Determines the latest snapshot date in the table, optionally restricted to
    snapshots on or before the provided date, and returns rows for the CVE IDs
    in cve_ids that exist at that snapshot date.

    Args:
        session: Active SQLAlchemy session.
        table: Snapshot table to query (e.g., EPSSsnapshot, KEVsnapshot).
        cve_ids (list): CVE identifiers to retrieve.
        date_column: Date column to use for ordering and filtering.
        selected_columns: Columns to include in result.
        date (optional): If provided, only snapshots on or before this date are considered.
    
    Returns:
        list: Snapshot rows for the supplied CVE IDs that exist at the latest
            available snapshot date. CVEs not present in that snapshot are not
            included.
    """

    snapshot_query = select(date_column)

    if date:
        snapshot_query = snapshot_query.where(date_column <= date)

    snapshot_date = (
        snapshot_query
        .order_by(date_column.desc())
        .limit(1)
        .scalar_subquery()
    )

    stmt = (
        select(*selected_columns)
        .where(table.cve_id.in_(cve_ids))
        .where(date_column == snapshot_date)
    )

    return session.execute(stmt).all()