"""ORM models for SBOM data, vulnerability intelligence, and prioritization results."""

from datetime import date, datetime, UTC

from .base import Base
from typing import List, Optional
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Column, Integer, String, ForeignKey, Identity, JSON, Float, Table, Date, DateTime, UniqueConstraint

component_dependency = Table(
    "component_dependency",
    Base.metadata,
    Column("parent_id", ForeignKey("sbom_component.id", ondelete="CASCADE"), primary_key=True),
    Column("child_id", ForeignKey("sbom_component.id", ondelete="CASCADE"), primary_key=True),
    Column("sbom_id", ForeignKey("sbom.id", ondelete="CASCADE"),primary_key=True)
)

csaf_vulnerability = Table(
    "csaf_vulnerability",
    Base.metadata,
    Column("csaf_id", ForeignKey("csaf_advisories.id", ondelete="CASCADE"), primary_key=True),
    Column("vulnerability_id", ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True),
)

finding_evidence = Table(
    "finding_evidence",
    Base.metadata,
    Column("finding_id", ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
    Column("evidence_id", ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True),
)

sbom_component = Table(
    "sbom_component",
    Base.metadata,
    Column("id", Integer, Identity(), primary_key=True),

    Column("sbom_id", ForeignKey("sbom.id", ondelete="CASCADE")),
    Column("component_id", ForeignKey("components.id", ondelete="CASCADE")),
    Column("bom_ref", String, nullable=False),

    UniqueConstraint("sbom_id", "bom_ref", name="uq_sbom_bomref")
)

vex_statement_component = Table(
    "vex_statement_component",
    Base.metadata,
    Column("statement_id", ForeignKey("vex_statements.id", ondelete="CASCADE"), primary_key=True),
    Column("component_id", ForeignKey("components.id", ondelete="CASCADE"), primary_key=True),
)

class SBOM(Base):
    """Stored SBOM metadata and its linked components and findings."""

    __tablename__ = 'sbom'
    id: Mapped[int] = mapped_column(Integer,Identity(), primary_key=True)
    sbom_version: Mapped[str] = mapped_column(String)
    bom_ref: Mapped[Optional[str]] = mapped_column(String, unique=True, nullable=True)
    timestamp: Mapped[date] = mapped_column(Date)
    serial_number: Mapped[Optional[str]] = mapped_column(String, unique=True, nullable=True)
    product_name: Mapped[str] = mapped_column(String)
    product_version: Mapped[str] = mapped_column(String)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    components: Mapped[List["Components"]] = relationship("Components", secondary=sbom_component, back_populates="sbom")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="sbom", cascade="all, delete-orphan")

class Components(Base):
    """Normalized software component records linked back to SBOMs and findings."""

    __tablename__ = 'components'
    id: Mapped[int] = mapped_column(Integer,Identity(), primary_key=True)
    type: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String)
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    purl: Mapped[Optional[str]] = mapped_column(String, unique=True, nullable=True, index=True)
    cpe: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    
    sbom: Mapped[List["SBOM"]] = relationship("SBOM", secondary=sbom_component, back_populates="components")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="component", cascade="all, delete-orphan")

    vex_statements: Mapped[List["VEXstatements"]] = relationship(
        "VEXstatements",
        secondary="vex_statement_component",
        back_populates="components"
    )

class Vulnerabilities(Base):
    """Canonical vulnerability records keyed by CVE identifier."""

    __tablename__ = 'vulnerabilities'
    id: Mapped[int] = mapped_column(Integer,Identity(), primary_key=True)
    cve_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    description: Mapped[str] = mapped_column(String)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cvss_source: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    published_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    
    csaf_advisories: Mapped[List["CSAFadvisories"]] = relationship(
        "CSAFadvisories",
        secondary=csaf_vulnerability,
        back_populates="vulnerabilities"
    )

    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="vulnerability", cascade="all, delete-orphan")

class VulnerabilityEnrichment(Base):
    """Enrichment records that store linked references, CWEs, and advisories."""

    __tablename__ = "vulnerability_enrichment"

    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.cve_id", ondelete="CASCADE")
    )
    data_type: Mapped[str] = mapped_column(String) # e.g., 'cwe', 'references', 'linked_advisories'
    source_provider: Mapped[str] = mapped_column(String) # e.g., 'cna', 'github', etc
    entity_id: Mapped[Optional[str]] = mapped_column(String, nullable=True) # e.g., CWE-79, GHSA-xxxx, etc
    url: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)

class KEVsnapshot(Base):
    """Historical snapshot of CVEs appearing in the CISA KEV catalog."""

    __tablename__ = 'kev_snapshot'

    __table_args__ = (
        UniqueConstraint("cve_id", "created_on", name="uq_kev_snapshot"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String, index=True) 
    shortDescription: Mapped[str] = mapped_column(String)
    catalog_added_date: Mapped[date] = mapped_column(Date)
    created_on: Mapped[date] = mapped_column(Date, default=lambda: date.today())


class EPSSsnapshot(Base):
    """Historical EPSS score snapshot for a CVE on a given date."""

    __tablename__ = 'epss_snapshot'

    __table_args__ = (
        UniqueConstraint("cve_id", "score_date", name="uq_epss_snapshot"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id"), index=True)
    epss_score: Mapped[float] = mapped_column(Float)
    percentile: Mapped[float] = mapped_column(Float)
    score_date: Mapped[date] = mapped_column(Date)
    created_on: Mapped[date] = mapped_column(Date, default=lambda: date.today())


class VEXdocuments(Base):
    """VEX document headers and their parsed statement collections."""

    __tablename__ = 'vex_documents'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[str] = mapped_column(String, unique=True, index=True)

    author: Mapped[str] = mapped_column(String)
    timestamp: Mapped[datetime] = mapped_column(DateTime)

    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    statements: Mapped[List["VEXstatements"]] = relationship("VEXstatements", back_populates="document", cascade="all, delete-orphan")  

class VEXstatements(Base):
    """Individual VEX statements tied to a document, SBOM, and vulnerability."""

    __tablename__ = 'vex_statements'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sbom_id: Mapped[Optional[int]] = mapped_column(ForeignKey("sbom.id"), nullable=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("vex_documents.id"), index=True)

    status: Mapped[str] = mapped_column(String)
    justification: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    vulnerability: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)

    document: Mapped["VEXdocuments"] = relationship("VEXdocuments", back_populates="statements")

    components: Mapped[List["Components"]]= relationship(
        "Components",
        secondary=vex_statement_component,
        back_populates="vex_statements"
    )

class CSAFadvisories(Base):
    """Stored CSAF advisories and the vulnerabilities they cover."""

    __tablename__ = 'csaf_advisories'
    id: Mapped[int] = mapped_column(Integer,Identity(), primary_key=True)
    csaf_id: Mapped[str] = mapped_column(String, unique=True, index=True)  # e.g., RHSA ID
    description: Mapped[str] = mapped_column(String)
    data: Mapped[JSON] = mapped_column(JSON)  # Store the entire CSAF advisory as JSON

    vulnerabilities: Mapped[List["Vulnerabilities"]] = relationship(
        "Vulnerabilities",
        secondary=csaf_vulnerability,
        back_populates="csaf_advisories"
    )


class Finding(Base):
    """Join table for a vulnerable component finding and its ranking output."""

    __tablename__ = 'findings'

    __table_args__ = (
        UniqueConstraint(
            "sbom_id",
            "component_id",
            "vulnerability_id",
            name="uq_finding_triplet"
        ),
    )

    id: Mapped[int] = mapped_column(Integer,Identity(), primary_key=True)

    sbom_id: Mapped[int] = mapped_column(ForeignKey("sbom.id"), index=True)
    component_id: Mapped[int] = mapped_column(ForeignKey("components.id"), index=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)

    sbom: Mapped["SBOM"] = relationship("SBOM", back_populates="findings")
    component: Mapped["Components"] = relationship("Components", back_populates="findings")
    vulnerability: Mapped["Vulnerabilities"] = relationship("Vulnerabilities", back_populates="findings")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    fusion_score: Mapped[float] = mapped_column(Float, index=True, nullable=False, default=0.0)
    rank: Mapped[int] = mapped_column(Integer, index=True, nullable=False, default=0)
    priority: Mapped[str] = mapped_column(String, nullable=False, default="Not yet evaluated.")
    why_ranked: Mapped[str] = mapped_column(String, nullable=False, default="Not yet evaluated.")
    last_updated: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))

    evidence_items: Mapped[List["Evidence"]] = relationship(
        "Evidence", 
        secondary=finding_evidence,
        back_populates="findings"
    )


class Evidence(Base):
    """Evidence items used to explain why a finding was created or ranked."""

    __tablename__ = 'evidence'
    id: Mapped[int] = mapped_column(Integer,Identity(), primary_key=True)
    evidence_type: Mapped[str] = mapped_column(String)
    source: Mapped[str] = mapped_column(String)
    cve_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    text_snippet: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    url_or_ref: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    findings: Mapped[List["Finding"]] = relationship(
        "Finding",
        secondary=finding_evidence,
        back_populates="evidence_items"
    )