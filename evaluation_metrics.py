import pathlib

from database import execute_select, Vulnerabilities, Finding, Components, KEVsnapshot, VEXstatements, SessionLocal, QueueSnapshot, QueueSnapshotItem, vex_statement_component
from collections import defaultdict
from typing import List
from services.sbom_service import get_all_sboms
from evaluation import evaluate_all_configs, build_vex_history
from config import config
from sqlalchemy import or_
import csv

from datetime import date, datetime

def evaluation(sbom_id: int, config_types: List[str]):
    with SessionLocal() as session:
        kev_rows = execute_select(
            session=session,
            selected_columns=[KEVsnapshot.cve_id, KEVsnapshot.snapshot_date, KEVsnapshot.catalog_added_date],
            where_conditions=[(KEVsnapshot.snapshot_date <= config.end_date)]
        )
        cve_ids = (row[0] for row in kev_rows)

        vex_rows = execute_select(
            session=session,
            selected_columns=[Vulnerabilities.cve_id, Components.purl, VEXstatements.status, VEXstatements.sbom_id, VEXstatements.timestamp],
            where_conditions=[or_(VEXstatements.sbom_id == sbom_id, VEXstatements.sbom_id.is_(None)), Vulnerabilities.cve_id.in_(cve_ids),
                              (VEXstatements.timestamp <= datetime.combine(config.end_date, datetime.max.time()))],
            joins=[(Vulnerabilities, VEXstatements.vulnerability == Vulnerabilities.id),
                   (vex_statement_component, VEXstatements.id == vex_statement_component.c.statement_id),
                   (Components, vex_statement_component.c.component_id == Components.id)
                ]
        )

        sbom_findings = execute_select(
            session=session,
            selected_columns=[Finding.id, Vulnerabilities.cve_id, Components.purl],
            where_conditions=[Finding.sbom_id == sbom_id],
            joins=[
                (Components, Finding.component_id == Components.id),
                (Vulnerabilities, Finding.vulnerability_id == Vulnerabilities.id),
            ]
        )

    sbom_findings_set = set((cve_id, purl) for _, cve_id, purl in sbom_findings)
    
    kev_added_dates = {row[0]: row[2] for row in kev_rows}

    kev_snapshots = defaultdict(set)
    for cve_id, snapshot_date, _ in kev_rows:
        kev_snapshots[snapshot_date].add(cve_id)

    vex_statements = build_vex_history(vex_rows)

    config_types_queues = {}

    for config_type in config_types:
        with SessionLocal() as session:

            snapshots = execute_select(
                session=session,
                selected_columns=[
                    QueueSnapshot.snapshot_date,
                    QueueSnapshotItem.finding_id,
                    Vulnerabilities.cve_id,
                    Components.purl,
                ],
                joins=[
                    (QueueSnapshotItem, QueueSnapshot.id == QueueSnapshotItem.queue_snapshot_id),
                    (Finding, QueueSnapshotItem.finding_id == Finding.id),
                    (Vulnerabilities, Finding.vulnerability_id == Vulnerabilities.id),
                    (Components, Finding.component_id == Components.id)
                ],
                where_conditions=[QueueSnapshot.sbom_id == sbom_id, QueueSnapshot.config_type == config_type],
                order_by=[QueueSnapshot.snapshot_date.asc(), QueueSnapshotItem.rank.asc()]
            )

        # Group flat rows by snapshot date
        grouped = defaultdict(list)
        for snap_date, finding_id, cve_id, purl in snapshots:
            item = (cve_id, purl)
            
            if item not in grouped[snap_date]:
                grouped[snap_date].append((cve_id, purl))

        snapshots_list = [{
                    "snapshot_date": date_str,
                    "findings": items
                }
            for date_str, items in grouped.items()]

        
        config_types_queues[config_type] = snapshots_list

    # Evaluate all configurations types
    evaluation_results = evaluate_all_configs(config_types_queues, kev_snapshots, kev_added_dates, vex_statements, sbom_findings_set)

    if evaluation_results:
        path = pathlib.Path(f"results/metrics/evaluation_results_{sbom_id}.csv")
        path.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists

        # Write results to CSV
        with open(path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=evaluation_results[0].keys())
            writer.writeheader()
            writer.writerows(evaluation_results)


if __name__ == "__main__":
    sboms = get_all_sboms()  # Ensure SBOMs are loaded before evaluation

    config_types = config.evaluation_config_types  # Load config types from config

    for sbom_id, _ in sboms:
        evaluation(sbom_id, config_types)