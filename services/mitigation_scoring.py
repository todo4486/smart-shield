"""Should something be done about this traffic, and what? (pure functions)

Input is what the models flagged recently plus measured or simulated rates. Output is an assessment per target, with
the evidence kept separate so an administrator can see why. None of the figures is a probability.

  confidence           mean share of forest trees voting attack, for flows the classifier flagged. For a host only the
                       anomaly detector flagged there are no such votes, so it is the share of that host's recent flows
                       that were flagged, and `confidence_basis` says so.
  severity             the same rule as alerts (attack type, number of flows, potential DDoS), raised to at least high
                       when the host takes a large share of the link, since then the harm is measured, not predicted.
  repetition           how many separate 10-second windows contain flagged flows: one burst is weak evidence.
  false_positive_risk  a documented heuristic from 0 to 1 (see false_positive_risk). A guide, not an estimate of error.

A congested link alone never produces an assessment: congestion does not mean attack. Only model verdicts start one.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set

from services import severity as severity_levels
from services.intrusion_inference_service import DDOS_MIN_SOURCES, severity_for

REPETITION_WINDOW_SECONDS = 10
ANOMALY_CATEGORY = "Anomalous flows"
HEAVY_SHARE = 0.30  # a host using this share of the link is doing measurable harm
NEGLIGIBLE_SHARE = 0.01


@dataclass(frozen=True)
class Thresholds:
    min_confidence: float = 0.70
    min_severity: str = "high"
    min_repetition: int = 3
    max_false_positive_risk: float = 0.60
    min_flagged_flows: int = 3  # below this the engine does not even recommend anything


@dataclass(frozen=True)
class FlaggedFlow:
    src_ip: str
    dst_ip: str
    category: str
    score: Optional[float]  # classifier vote share; not a probability
    at_seconds: float


@dataclass
class Assessment:
    target_kind: str  # "source" or "destination"
    target: str
    category: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    flagged_flows: int
    flag_share: float
    confidence: float
    confidence_basis: str  # "classifier_votes" or "flag_share"
    severity: str
    repetition: int
    false_positive_risk: float
    risk_reasons: List[str]
    traffic_bps: Optional[float]
    share_of_link: Optional[float]
    distinct_sources: int
    critical_target: bool
    recommended_action: str  # "rate_limit" or "block"
    auto_eligible: bool
    auto_blockers: List[str] = field(default_factory=list)
    upstream_required: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def repetition_count(times: Iterable[float], window_seconds: int = REPETITION_WINDOW_SECONDS) -> int:
    return len({int(t // window_seconds) for t in times})


def false_positive_risk(*, anomaly_only: bool, flag_share: float, repetition: int, critical_target: bool,
                        share_of_link: Optional[float]) -> tuple:
    """Starts at 0.2 (0.5 if only the anomaly detector flagged it) and rises for each reason to doubt. Capped at 1."""
    risk, reasons = (0.5, ["Only the anomaly detector flagged this; no model named an attack."]) if anomaly_only else (0.2, [])
    if flag_share < 0.5:
        risk += 0.3
        reasons.append(f"Only {flag_share:.0%} of this target's recent flows were flagged.")
    if repetition < 2:
        risk += 0.2
        reasons.append("Flagged in a single burst only.")
    if critical_target:
        risk += 0.5  # enough on its own to keep the engine from limiting a critical host by itself
        reasons.append("This host carries traffic marked critical.")
    if share_of_link is not None and share_of_link < NEGLIGIBLE_SHARE:
        risk += 0.1
        reasons.append("It uses almost no bandwidth, so a limit has little benefit.")
    return min(1.0, round(risk, 4)), reasons


def _severity(category: str, count: int, ddos: bool, share_of_link: Optional[float]) -> str:
    level = severity_for(category, count, "anomaly" if category == ANOMALY_CATEGORY else "security", ddos)
    if share_of_link is not None and share_of_link >= HEAVY_SHARE and severity_levels.rank(level) < severity_levels.rank("high"):
        return "high"
    return level


def _top(values: Iterable[str]) -> str:
    counts: Dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return min(counts, key=lambda k: (-counts[k], k))


def _assess(kind: str, target: str, flows: Sequence[FlaggedFlow], total_flows: int, *, rate_bps: Optional[float],
            capacity_bps: Optional[float], critical: bool, thresholds: Thresholds, ddos: bool) -> Assessment:
    category = _top(f.category for f in flows)
    votes = [f.score for f in flows if f.category != ANOMALY_CATEGORY and f.score is not None]
    flag_share = min(1.0, len(flows) / total_flows) if total_flows else 1.0
    anomaly_only = not votes
    confidence = flag_share if anomaly_only else sum(votes) / len(votes)
    repetition = repetition_count(f.at_seconds for f in flows)
    share = rate_bps / capacity_bps if rate_bps is not None and capacity_bps else None
    risk, reasons = false_positive_risk(anomaly_only=anomaly_only, flag_share=flag_share, repetition=repetition,
                                        critical_target=critical, share_of_link=share)
    level = _severity(category, len(flows), ddos, share)
    blockers: List[str] = []
    if confidence < thresholds.min_confidence:
        blockers.append(f"confidence {confidence:.2f} is below {thresholds.min_confidence:.2f}")
    if severity_levels.rank(level) < severity_levels.rank(thresholds.min_severity):
        blockers.append(f"severity {level} is below {thresholds.min_severity}")
    if repetition < thresholds.min_repetition:
        blockers.append(f"seen in {repetition} window(s), needs {thresholds.min_repetition}")
    if risk > thresholds.max_false_positive_risk:
        blockers.append(f"false-positive risk {risk:.2f} is above {thresholds.max_false_positive_risk:.2f}")
    # A host using little bandwidth is not helped by a bandwidth limit, so only a block would change anything.
    action = "block" if kind == "source" and share is not None and share < NEGLIGIBLE_SHARE else "rate_limit"
    if action != "rate_limit":
        blockers.append("the recommended action is a block, which always needs an administrator")
    sources = {f.src_ip for f in flows}
    return Assessment(
        kind, target, category, target if kind == "source" else None if len(sources) > 1 else next(iter(sources)),
        target if kind == "destination" else _top(f.dst_ip for f in flows), len(flows), round(flag_share, 4),
        round(confidence, 4), "flag_share" if anomaly_only else "classifier_votes", level, repetition, risk, reasons,
        rate_bps, None if share is None else round(share, 4), len(sources), critical, action, not blockers, blockers,
        upstream_required=kind == "destination")


def assess_targets(flagged: Sequence[FlaggedFlow], flow_totals: Mapping[str, int], sent_bps: Mapping[str, float],
                   received_bps: Mapping[str, float], capacity_bps: Optional[float], critical_hosts: Set[str],
                   thresholds: Thresholds) -> List[Assessment]:
    """One assessment per target. Many sources converging on one destination is one target: that destination."""
    by_destination: Dict[str, List[FlaggedFlow]] = {}
    for flow in flagged:
        by_destination.setdefault(flow.dst_ip, []).append(flow)
    results: List[Assessment] = []
    grouped_sources: Set[str] = set()
    for destination, flows in sorted(by_destination.items()):
        sources = {f.src_ip for f in flows}
        if len(sources) >= DDOS_MIN_SOURCES:
            grouped_sources |= sources
            total = sum(flow_totals.get(s, 0) for s in sources)
            results.append(_assess("destination", destination, flows, total, rate_bps=received_bps.get(destination),
                                   capacity_bps=capacity_bps, critical=destination in critical_hosts,
                                   thresholds=thresholds, ddos=True))
    by_source: Dict[str, List[FlaggedFlow]] = {}
    for flow in flagged:
        if flow.src_ip not in grouped_sources:
            by_source.setdefault(flow.src_ip, []).append(flow)
    for source, flows in sorted(by_source.items()):
        results.append(_assess("source", source, flows, flow_totals.get(source, len(flows)), rate_bps=sent_bps.get(source),
                               capacity_bps=capacity_bps, critical=source in critical_hosts, thresholds=thresholds,
                               ddos=False))
    return [a for a in results if a.flagged_flows >= thresholds.min_flagged_flows]


def verify_recovery(action_type: str, before: Mapping[str, Any], after: Mapping[str, Any],
                    limit_bps: Optional[float], loss_tolerance: float = 0.01) -> tuple:
    """(status, note) from samples before and after. Says 'unavailable' rather than guessing when samples are missing."""
    if not after.get("samples"):
        return "unavailable", "No samples were stored after the action, so recovery cannot be judged."
    target_after, loss_after = after.get("target_bps"), after.get("loss_ratio")
    ceiling = 0.0 if action_type in ("block", "isolate") else limit_bps
    contained = None
    if ceiling is not None and target_after is not None:
        contained = target_after <= ceiling * 1.1 + 1.0
    if contained is False:
        return "not_recovered", f"The target still uses {target_after / 1e6:,.2f} Mbit/s, above the limit."
    if loss_after is None:
        return "partial", "The target is contained, but packet loss is not measured here, so link recovery is unknown."
    if loss_after <= loss_tolerance:
        before_loss = before.get("loss_ratio")
        if before_loss is not None and before_loss > loss_tolerance:
            return "recovered", f"Loss fell from {before_loss:.1%} to {loss_after:.1%} and the target is within its limit."
        return "recovered", "The target is within its limit. The link had no loss before the action either."
    if contained:
        return "partial", (f"The target is contained, but the link still loses {loss_after:.1%}. Traffic is filling the link "
                           "before it reaches this controller, so mitigation must happen upstream (ISP or scrubbing service).")
    return "not_recovered", f"The link still loses {loss_after:.1%}."
