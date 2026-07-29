"""Governance: chain-of-custody, evidence hashing, IOC management, provenance.

This module fills the forensic-governance gaps that separate a research tool
from a commercial DFIR product: every piece of evidence is hashed on intake,
a tamper-evident chain-of-custody form is produced, and IOCs (indicators of
compromise) are accumulated and persisted for enrichment.

Submodules:
  - ``hashing``   : SHA-256 / MD5 file hashing (intake fingerprinting).
  - ``custody``   : chain-of-custody forms with an integrity seal.
  - ``ioc_store`` : accumulate + persist IOCs per investigation.
"""

from __future__ import annotations
