"""MITRE ATT&CK mapping for attack-type labels: a static, offline table (pure).

Each CIC-IDS2017-style label maps to the ATT&CK (Enterprise) tactic and technique that best describes
the behaviour the label stands for. The mapping is label-level and approximate: it says what kind of
activity the model's category usually is, not that a specific technique was confirmed on the network.
Labels with no sensible mapping (benign traffic, anomalies, unclassified attacks, congestion) get none,
rather than a guess. Technique pages: https://attack.mitre.org/techniques/<id>/ (shown as text only;
the app never fetches them).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from services.intrusion_features import clean_label


@dataclass(frozen=True)
class Technique:
    tactic: str
    tactic_id: str
    technique_id: str
    technique: str

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}/"


_DISCOVERY = ("Discovery", "TA0007")
_CREDENTIAL_ACCESS = ("Credential Access", "TA0006")
_IMPACT = ("Impact", "TA0040")
_INITIAL_ACCESS = ("Initial Access", "TA0001")
_COMMAND_AND_CONTROL = ("Command and Control", "TA0011")

# Order matters: the first pattern that matches wins (e.g. "Web Attack – Brute Force" is brute force, and
# "DDoS" must be tested before plain "DoS").
_TABLE: Tuple[Tuple[re.Pattern, Tuple[Technique, ...]], ...] = (
    (re.compile(r"port\s*scan", re.I), (Technique(*_DISCOVERY, "T1046", "Network Service Discovery"),)),
    (re.compile(r"patator|brute\s*force", re.I),
     (Technique(*_CREDENTIAL_ACCESS, "T1110", "Brute Force"),
      Technique(*_CREDENTIAL_ACCESS, "T1110.001", "Brute Force: Password Guessing"))),
    (re.compile(r"\bddos\b", re.I),
     (Technique(*_IMPACT, "T1498", "Network Denial of Service"),
      Technique(*_IMPACT, "T1498.001", "Network Denial of Service: Direct Network Flood"))),
    (re.compile(r"\bdos\b|hulk|goldeneye|slowloris|slowhttptest", re.I),
     (Technique(*_IMPACT, "T1499", "Endpoint Denial of Service"),
      Technique(*_IMPACT, "T1499.002", "Endpoint Denial of Service: Service Exhaustion Flood"))),
    (re.compile(r"sql\s*injection", re.I), (Technique(*_INITIAL_ACCESS, "T1190", "Exploit Public-Facing Application"),)),
    (re.compile(r"\bxss\b|cross.site", re.I), (Technique(*_INITIAL_ACCESS, "T1189", "Drive-by Compromise"),)),
    (re.compile(r"heartbleed", re.I), (Technique(*_INITIAL_ACCESS, "T1190", "Exploit Public-Facing Application"),)),
    (re.compile(r"infiltration", re.I), (Technique(*_INITIAL_ACCESS, "T1190", "Exploit Public-Facing Application"),)),
    (re.compile(r"\bbot\b|botnet", re.I),
     (Technique(*_COMMAND_AND_CONTROL, "T1071", "Application Layer Protocol"),)),
)

NOT_MAPPED = ("BENIGN", "NORMAL", "Anomalous flows", "Attack (unclassified)")


def techniques_for(label: Optional[str]) -> List[Technique]:
    """ATT&CK techniques for an attack-type label; [] when there is no honest mapping (pure)."""
    if not label:
        return []
    cleaned = clean_label(str(label))
    if cleaned.upper() in (n.upper() for n in NOT_MAPPED):
        return []
    for pattern, techniques in _TABLE:
        if pattern.search(cleaned):
            return list(techniques)
    return []


def primary(label: Optional[str]) -> Optional[Technique]:
    """The parent technique shown on badges (pure)."""
    found = techniques_for(label)
    return found[0] if found else None


# Kill-chain order used when several tactics are shown together.
TACTIC_ORDER = tuple(t[0] for t in (_INITIAL_ACCESS, _CREDENTIAL_ACCESS, _DISCOVERY, _COMMAND_AND_CONTROL, _IMPACT))


def tactics_for(labels: Iterable[str]) -> List[str]:
    """Distinct tactics across several labels, in kill-chain order (pure)."""
    found = {t.tactic for label in labels for t in techniques_for(label)}
    return [t for t in TACTIC_ORDER if t in found]


def primaries_for(labels: Iterable[str]) -> List[Technique]:
    """Distinct parent techniques across several labels (an incident's alerts), in kill-chain order (pure)."""
    unique = {t.technique_id: t for label in labels if (t := primary(label))}
    return sorted(unique.values(), key=lambda t: (TACTIC_ORDER.index(t.tactic), t.technique_id))
