from .bandit import BanditAdapter
from .gitleaks import GitleaksAdapter
from .npm_audit import NpmAuditAdapter
from .osv import OsvScannerAdapter
from .pip_audit import PipAuditAdapter
from .semgrep import SemgrepAdapter

ALL_ADAPTERS = [SemgrepAdapter, BanditAdapter, GitleaksAdapter, OsvScannerAdapter, PipAuditAdapter, NpmAuditAdapter]
