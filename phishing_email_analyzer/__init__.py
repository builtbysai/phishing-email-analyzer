"""Dependency-free phishing email analysis."""

from .analyzer import analyze_email, analyze_file, analyze_path
from .models import EmailAnalysis, Finding

__all__ = ["EmailAnalysis", "Finding", "analyze_email", "analyze_file", "analyze_path"]
__version__ = "1.0.0"
