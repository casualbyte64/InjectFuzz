from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
from .baseline import Baseline
from .request_engine import ResponseData

class Classification(Enum):
    INTERESTING = "INTERESTING"
    ANOMALY = "ANOMALY"
    ERROR = "ERROR"
    UNINTERESTING = "UNINTERESTING"

@dataclass(slots=True)
class AnalysisResult:
    """
    The verdict for a single injection.
    slots=True for memory efficiency.
    """
    classification: Classification
    reason: str
    diff_score: float
    payload: str
    injection_point: str  # <--- ADDED THIS FIELD
    response: ResponseData

class Analyzer:
    """
    Professional Differential Analysis Engine.
    """
    
    def __init__(self, baseline: Baseline):
        self.baseline = baseline

    # ADDED injection_point argument here
    def analyze(self, response: ResponseData, payload: str, injection_point: str) -> AnalysisResult:
        """
        Compare injected response against the statistical baseline.
        """
        score = 0.0
        reasons: List[str] = []

        # 1. Critical Error Detection
        if response.status_code == 0:
            return self._result(
                Classification.ERROR, 
                f"Connection Failure: {response.text[:50]}", 
                1.0, payload, injection_point, response
            )
        
        if response.status_code >= 500:
            return self._result(
                Classification.ERROR, 
                f"Server Error {response.status_code}", 
                1.0, payload, injection_point, response
            )

        # 2. Status Code Analysis
        if response.status_code != self.baseline.status_code:
            score += 0.5
            reasons.append(f"Status: {self.baseline.status_code}->{response.status_code}")

        # 3. Reflection Analysis
        if payload in response.text:
            score += 0.8
            reasons.append("Payload Reflected")

        # 4. Content Length Analysis (Statistical)
        diff = abs(response.content_length - self.baseline.avg_content_length)
        is_size_anomaly = False
        
        if self.baseline.stdev_content_length > 0:
            # Dynamic Target: Use StDev (3-sigma rule)
            if diff > (3 * self.baseline.stdev_content_length):
                is_size_anomaly = True
        else:
            # Static Target: Use Percentage (5%)
            if self.baseline.avg_content_length > 0:
                percent_diff = diff / self.baseline.avg_content_length
                if percent_diff > 0.05:
                    is_size_anomaly = True
        
        if is_size_anomaly:
            score += 0.4
            reasons.append(f"Size Deviation ({int(diff)} bytes)")

        # 5. Timing Analysis
        time_threshold = self.baseline.avg_response_time + (3 * self.baseline.stdev_response_time) + 2.0
        if response.response_time > time_threshold:
            score += 0.3
            reasons.append(f"High Latency (+{response.response_time - self.baseline.avg_response_time:.2f}s)")

        # 6. Final Scoring
        if score >= 0.8:
            cls = Classification.INTERESTING
        elif score >= 0.3:
            cls = Classification.ANOMALY
        else:
            cls = Classification.UNINTERESTING

        return self._result(
            cls, 
            ", ".join(reasons) if reasons else "Matches Baseline", 
            score, payload, injection_point, response
        )

    # UPDATED helper to accept injection_point
    def _result(self, cls, reason, score, payload, inj_point, resp):
        return AnalysisResult(cls, reason, score, payload, inj_point, resp)