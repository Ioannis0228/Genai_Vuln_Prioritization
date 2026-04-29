from datetime import date
from .base import Base
from typing import List, Optional
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Column, Integer, String, ForeignKey, Identity, JSON, Float, Table, Date

component_dependency = Table(
    "component_dependency",
    Base.metadata,
    Column("parent_id", ForeignKey("components.id"), primary_key=True),
    Column("child_id", ForeignKey("components.id"), primary_key=True),
)

csaf_vulnerability = Table(
    "csaf_vulnerability",
    Base.metadata,
    Column("csaf_id", ForeignKey("csaf_advisories.id"), primary_key=True),
    Column("vulnerability_id", ForeignKey("vulnerabilities.id"), primary_key=True),
)

component_vulnerability = Table(
    "component_vulnerability",
    Base.metadata,
    Column("component_id", ForeignKey("components.id"), primary_key=True),
    Column("vulnerability_id", ForeignKey("vulnerabilities.id"), primary_key=True),
)

class Components(Base):
    __tablename__ = 'components'
    id: Mapped[int] = mapped_column(Integer,Identity(), primary_key=True)
    type: Mapped[str] = mapped_column(String)
    bom_ref: Mapped[Optional[str]] = mapped_column(String, unique=True, nullable=True)
    name: Mapped[str] = mapped_column(String)
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    purl: Mapped[Optional[str]] = mapped_column(String, unique=True, nullable=True, index=True)
    cpe: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    vulnerabilities: Mapped[List["Vulnerabilities"]] = relationship(
        "Vulnerabilities", secondary=component_vulnerability, back_populates="components")

    # Components this depends on
    dependencies: Mapped[List["Components"]] = relationship(
        "Components",
        secondary=component_dependency,
        primaryjoin=id==component_dependency.c.parent_id,
        secondaryjoin=id==component_dependency.c.child_id,
        back_populates="dependents")
    
    # Components that depend on this
    dependents: Mapped[List["Components"]] = relationship(
        "Components",
        secondary=component_dependency,
        primaryjoin=id==component_dependency.c.child_id,
        secondaryjoin=id==component_dependency.c.parent_id,
        back_populates="dependencies")

class Vulnerabilities(Base):
    __tablename__ = 'vulnerabilities'
    id: Mapped[int] = mapped_column(Integer,Identity(), primary_key=True)
    cve_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    description: Mapped[str] = mapped_column(String)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cvss_source: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    published_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)

    components: Mapped[List["Components"]] = relationship(
        "Components",
        secondary=component_vulnerability,
        back_populates="vulnerabilities")
    
    csaf_advisories: Mapped[List["CSAFadvisories"]] = relationship(
        "CSAFadvisories",
        secondary=csaf_vulnerability,
        back_populates="vulnerabilities"
    )

    # Add other relevant fields as needed
    # e.g., CVSS vector, references, etc.

class KEVsnapshot(Base):
    __tablename__ = 'kev_snapshot'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    shortDescription: Mapped[str] = mapped_column(String)
    dateAdded: Mapped[Date] = mapped_column(Date)


class EPSSsnapshot(Base):
    __tablename__ = 'epss_snapshot'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.cve_id"), unique=True, index=True)
    epss_score: Mapped[float] = mapped_column(Float)
    percentile: Mapped[float] = mapped_column(Float)
    date: Mapped[Date] = mapped_column(Date)


class VEX(Base):
    __tablename__ = 'vex'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    status: Mapped[str] = mapped_column(String)
    justification: Mapped[str] = mapped_column(String)
    # Add other relevant fields as needed


class CSAFadvisories(Base):
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

class Evidence(Base):
    __tablename__ = 'evidence'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_type: Mapped[str] = mapped_column(String)
    timestamp: Mapped[date] = mapped_column(Date)
    text_snippet: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    url_or_ref: Mapped[Optional[str]] = mapped_column(String, nullable=True)