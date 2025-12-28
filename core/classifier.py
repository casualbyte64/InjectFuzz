from enum import Enum, auto
from typing import Set, Dict
from .analyzer import AnalysisResult, Classification as AnalyzerClassification

class SignalType(Enum):
    # High Confidence (Direct evidence of break/execution)
    BACKEND_ERROR = auto()      # 500s, Stack traces
    REFLECTION = auto()         # Payload returned verbatim
    
    # Medium Confidence (Strong behavioral shifts)
    STATUS_CHANGE = auto()      # 200 -> 403, 200 -> 302
    SIZE_ANOMALY = auto()       # Significant content length change
    TIMING_ANOMALY = auto()     # Significant delay (SQLi/ReDoS)
    
    # Low Confidence (Weak indicators)
    LINE_COUNT_ANOMALY = auto()
    CONTENT_HASH_CHANGE = auto()

class VulnerabilityLabel(Enum):
    POSSIBLE_INJECTION = "possible_injection"
    ANOMALY = "anomaly"
    NO_ISSUE = "no_issue"

class Classifier:
    """
    Professional Policy Engine.
    Translates technical analysis into actionable triage labels.
    
    Philosophy: Bias towards False Negatives. 
    If we aren't sure, it's an 'ANOMALY', not 'POSSIBLE_INJECTION'.
    """

    def __init__(self):
        # Configuration: Which signals map to which confidence tier?
        self.HIGH_CONFIDENCE = {SignalType.BACKEND_ERROR, SignalType.REFLECTION}
        self.MEDIUM_CONFIDENCE = {SignalType.STATUS_CHANGE, SignalType.SIZE_ANOMALY, SignalType.TIMING_ANOMALY}
        self.LOW_CONFIDENCE = {SignalType.LINE_COUNT_ANOMALY, SignalType.CONTENT_HASH_CHANGE}

    def classify(self, result: AnalysisResult) -> str:
        """
        Takes the raw AnalysisResult and applies the 'Conservative' policy.
        Returns string label: 'possible_injection', 'anomaly', or 'no_issue'.
        """
        signals = self._extract_signals(result)
        
        if not signals:
            return VulnerabilityLabel.NO_ISSUE.value

        # 1. High Confidence Rule
        # If any High Confidence signal is present, we escalate immediately.
        if not signals.isdisjoint(self.HIGH_CONFIDENCE):
            return VulnerabilityLabel.POSSIBLE_INJECTION.value

        # 2. Medium Confidence Rule (The "Two Witness" Rule)
        # We need at least 2 Medium signals OR 1 Medium + 1 Low to call it "Possible Injection".
        medium_matches = signals.intersection(self.MEDIUM_CONFIDENCE)
        low_matches = signals.intersection(self.LOW_CONFIDENCE)
        
        medium_count = len(medium_matches)
        low_count = len(low_matches)

        if medium_count >= 2:
            return VulnerabilityLabel.POSSIBLE_INJECTION.value
        
        if medium_count == 1 and low_count >= 1:
            return VulnerabilityLabel.POSSIBLE_INJECTION.value
            
        # 3. Default to Anomaly
        # If we have signals, but they aren't strong enough to convict.
        return VulnerabilityLabel.ANOMALY.value

    def _extract_signals(self, result: AnalysisResult) -> Set[SignalType]:
        """
        Parses the text/score from AnalysisResult into strict Enums.
        This adapts Phase 4 output to Phase 5 logic.
        """
        detected = set()
        
        # Parse the 'reason' string from Analyzer
        # (In a monolithic tool, we'd pass these as objects, but we are parsing the Result object)
        reason_str = result.reason.lower()

        if "server error" in reason_str or result.response.status_code >= 500:
            detected.add(SignalType.BACKEND_ERROR)
            
        if "reflected" in reason_str:
            detected.add(SignalType.REFLECTION)

        if "status:" in reason_str or "status change" in reason_str:
            detected.add(SignalType.STATUS_CHANGE)
            
        if "size deviation" in reason_str:
            detected.add(SignalType.SIZE_ANOMALY)
            
        if "time" in reason_str or "latency" in reason_str:
            detected.add(SignalType.TIMING_ANOMALY)

        return detected