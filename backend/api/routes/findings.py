"""
Findings Management API Routes
Endpoints for managing security findings.
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from ...models.database import get_db
from ...models.schemas import FindingModel, SeverityLevel, SessionModel

router = APIRouter()


class CreateFindingRequest(BaseModel):
    """Request body for creating a new finding."""
    session_id: str
    target_id: Optional[str] = None
    title: str = Field(..., min_length=1, max_length=500)
    description: str
    severity: str = Field(..., pattern="^(info|low|medium|high|critical)$")
    category: str
    evidence: str = ""
    remediation: str = ""
    cve_ids: List[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None


class VerifyFindingRequest(BaseModel):
    """Request body for verifying a finding."""
    verified: bool
    verified_by: str = Field(default="user")


class FindingResponse(BaseModel):
    """Response model for finding data."""
    id: str
    session_id: str
    target_id: Optional[str]
    title: str
    description: str
    severity: str
    category: str
    evidence: str
    remediation: str
    cve_ids: List[str]
    cvss_score: Optional[float]
    verified: bool
    discovered_at: datetime
    discovered_by: str


class FindingsSummary(BaseModel):
    """Summary of findings."""
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    verified: int
    unverified: int


@router.post("", response_model=FindingResponse)
async def create_finding(
    request: CreateFindingRequest,
    db: AsyncSession = Depends(get_db)
):
    """Create a new security finding."""
    finding = FindingModel(
        id=str(uuid.uuid4()),
        session_id=request.session_id,
        target_id=request.target_id,
        title=request.title,
        description=request.description,
        severity=SeverityLevel(request.severity),
        category=request.category,
        evidence=request.evidence,
        remediation=request.remediation,
        cve_ids=request.cve_ids,
        cvss_score=request.cvss_score,
        discovered_by="api"
    )

    db.add(finding)
    await db.commit()

    return FindingResponse(
        id=finding.id,
        session_id=finding.session_id,
        target_id=finding.target_id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity.value,
        category=finding.category,
        evidence=finding.evidence,
        remediation=finding.remediation,
        cve_ids=finding.cve_ids,
        cvss_score=finding.cvss_score,
        verified=finding.verified,
        discovered_at=finding.discovered_at,
        discovered_by=finding.discovered_by
    )


@router.get("/session/{session_id}")
async def list_findings(
    session_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    verified: Optional[bool] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all findings for a session."""
    query = select(FindingModel).where(FindingModel.session_id == session_id)

    if severity:
        query = query.where(FindingModel.severity == SeverityLevel(severity))

    if category:
        query = query.where(FindingModel.category == category)

    if verified is not None:
        query = query.where(FindingModel.verified == verified)

    query = query.order_by(
        FindingModel.severity.desc(),
        FindingModel.discovered_at.desc()
    )

    result = await db.execute(query)
    findings = result.scalars().all()

    return {
        "findings": [
            FindingResponse(
                id=f.id,
                session_id=f.session_id,
                target_id=f.target_id,
                title=f.title,
                description=f.description,
                severity=f.severity.value,
                category=f.category,
                evidence=f.evidence,
                remediation=f.remediation,
                cve_ids=f.cve_ids,
                cvss_score=f.cvss_score,
                verified=f.verified,
                discovered_at=f.discovered_at,
                discovered_by=f.discovered_by
            )
            for f in findings
        ],
        "total": len(findings)
    }


@router.get("/session/{session_id}/summary", response_model=FindingsSummary)
async def get_findings_summary(
    session_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get a summary of findings for a session."""
    result = await db.execute(
        select(FindingModel).where(FindingModel.session_id == session_id)
    )
    findings = result.scalars().all()

    summary = {
        "total": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "verified": 0,
        "unverified": 0
    }

    for f in findings:
        summary[f.severity.value] += 1
        if f.verified:
            summary["verified"] += 1
        else:
            summary["unverified"] += 1

    return FindingsSummary(**summary)


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get a specific finding by ID."""
    result = await db.execute(
        select(FindingModel).where(FindingModel.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingResponse(
        id=finding.id,
        session_id=finding.session_id,
        target_id=finding.target_id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity.value,
        category=finding.category,
        evidence=finding.evidence,
        remediation=finding.remediation,
        cve_ids=finding.cve_ids,
        cvss_score=finding.cvss_score,
        verified=finding.verified,
        discovered_at=finding.discovered_at,
        discovered_by=finding.discovered_by
    )


@router.post("/{finding_id}/verify")
async def verify_finding(
    finding_id: str,
    request: VerifyFindingRequest,
    db: AsyncSession = Depends(get_db)
):
    """Verify or unverify a finding."""
    result = await db.execute(
        select(FindingModel).where(FindingModel.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.verified = request.verified
    finding.verified_by = request.verified_by
    finding.verified_at = datetime.utcnow() if request.verified else None

    await db.commit()

    return {
        "status": "verified" if request.verified else "unverified",
        "finding_id": finding_id
    }


@router.put("/{finding_id}")
async def update_finding(
    finding_id: str,
    request: CreateFindingRequest,
    db: AsyncSession = Depends(get_db)
):
    """Update a finding."""
    result = await db.execute(
        select(FindingModel).where(FindingModel.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.title = request.title
    finding.description = request.description
    finding.severity = SeverityLevel(request.severity)
    finding.category = request.category
    finding.evidence = request.evidence
    finding.remediation = request.remediation
    finding.cve_ids = request.cve_ids
    finding.cvss_score = request.cvss_score

    await db.commit()

    return {"status": "updated", "finding_id": finding_id}


@router.delete("/{finding_id}")
async def delete_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Delete a finding."""
    result = await db.execute(
        select(FindingModel).where(FindingModel.id == finding_id)
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    await db.delete(finding)
    await db.commit()

    return {"status": "deleted", "finding_id": finding_id}


@router.get("/session/{session_id}/export")
async def export_findings(
    session_id: str,
    format: str = "json",
    db: AsyncSession = Depends(get_db)
):
    """Export findings in various formats."""
    result = await db.execute(
        select(FindingModel).where(FindingModel.session_id == session_id)
    )
    findings = result.scalars().all()

    if format == "json":
        return {
            "session_id": session_id,
            "export_date": datetime.utcnow().isoformat(),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "category": f.category,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "cve_ids": f.cve_ids,
                    "cvss_score": f.cvss_score,
                    "verified": f.verified,
                    "discovered_at": f.discovered_at.isoformat()
                }
                for f in findings
            ]
        }

    elif format == "markdown":
        md = f"# Security Findings Report\n\n"
        md += f"Session: {session_id}\n"
        md += f"Export Date: {datetime.utcnow().isoformat()}\n\n"

        for severity in ["critical", "high", "medium", "low", "info"]:
            severity_findings = [
                f for f in findings
                if f.severity.value == severity
            ]
            if severity_findings:
                md += f"## {severity.upper()} Severity\n\n"
                for f in severity_findings:
                    md += f"### {f.title}\n\n"
                    md += f"**Category:** {f.category}\n\n"
                    md += f"**Description:** {f.description}\n\n"
                    if f.evidence:
                        md += f"**Evidence:**\n```\n{f.evidence}\n```\n\n"
                    if f.remediation:
                        md += f"**Remediation:** {f.remediation}\n\n"
                    md += "---\n\n"

        return {"content": md, "format": "markdown"}

    else:
        raise HTTPException(status_code=400, detail="Unsupported export format")
