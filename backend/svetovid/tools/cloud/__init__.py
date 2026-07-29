"""Cloud control-plane investigation tools.

Sub-package for API-based (host-run, non-sandboxed) tools that audit a cloud
or SaaS control plane directly, e.g. GCP Cloud Logging / Security Command
Center. Tools here follow the same :class:`~svetovid.tools.base.Tool` contract
as the disk-image tools but carry ``image=None`` / ``sandboxed=False`` because
the evidence lives in the cloud API, not on a mounted image.
"""
