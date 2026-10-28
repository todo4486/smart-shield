"""Which kind of data a widget is showing: LIVE, COUNTERS, DATASET or DATASET REPLAY (pure).

* LIVE:            live capture with passive packet/flow analysis running now.
* COUNTERS:        live capture in interface-counter mode (rates only, no flows).
* DATASET:         imported telemetry, flow records or a registered dataset.
* DATASET REPLAY:  a labelled dataset replayed through the pipeline (never live traffic).
* NO DATA:         nothing stored yet.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

LIVE = "live"
COUNTERS = "counters"
DATASET = "dataset"
REPLAY = "replay"
NONE = "none"

LABELS = {LIVE: "LIVE", COUNTERS: "COUNTERS", DATASET: "DATASET", REPLAY: "DATASET REPLAY", NONE: "NO DATA"}
DESCRIPTIONS = {
    LIVE: "Passive capture running now: interface counters plus flows from packets.",
    COUNTERS: "Passive capture running now in interface-counter mode: rates only, no flows.",
    DATASET: "Imported or registered data, not live traffic.",
    REPLAY: "A labelled dataset replayed through the pipeline. Nothing here is live traffic.",
    NONE: "Nothing has been captured or imported yet.",
}


@dataclass(frozen=True)
class DataSource:
    kind: str
    detail: Optional[str] = None

    @property
    def label(self) -> str:
        return LABELS[self.kind]

    @property
    def description(self) -> str:
        return DESCRIPTIONS[self.kind]


def classify(source_type: Optional[str], *, live_running: bool = False, live_mode: Optional[str] = None,
             detail: Optional[str] = None) -> DataSource:
    """Badge for a session. A live session only counts as LIVE/COUNTERS while capture is running."""
    if source_type == "replay":
        return DataSource(REPLAY, detail)
    if source_type == "live_capture" and live_running:
        return DataSource(LIVE if live_mode == "packets" else COUNTERS, detail)
    if source_type in ("live_capture", "dataset", "historical_import", "flow_import"):
        # A finished live capture is stored data now: it is not presented as live.
        return DataSource(DATASET, detail)
    return DataSource(NONE, detail)
