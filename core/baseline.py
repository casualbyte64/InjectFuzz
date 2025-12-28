import statistics
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from .request_engine import RequestEngine, ResponseData

# Module Logger
logger = logging.getLogger("SignalFuzz.Baseline")

@dataclass(slots=True)
class Baseline:
    """
    The Mathematical Model of 'Normalcy'.
    Stores not just averages, but the 'Variance' (jitter) of the target.
    """
    url: str
    method: str
    status_code: int
    
    # Statistical Models
    avg_content_length: float
    stdev_content_length: float  # The "Noise Floor" for size
    
    avg_response_time: float
    stdev_response_time: float   # The "Noise Floor" for timing
    
    avg_line_count: float
    
    # Structural Integrity
    reference_hash: str          # Hash of the most "standard" response
    is_stable: bool              # If False, the target is too chaotic for reliable fuzzing
    stability_score: float       # 0.0 (Chaos) to 1.0 (Static)

class BaselineEngine:
    """
    Professional Baseline Acquisition.
    - Uses statistical sampling (N=5 default)
    - Rejects outliers automatically
    - Calculates the 'Stability Score' of the target
    """
    
    def __init__(self, request_engine: RequestEngine, samples: int = 5):
        self.req_engine = request_engine
        self.samples = max(3, samples) # Force minimum 3 samples for math to work
        
    def calibrate(
        self, 
        url: str, 
        method: str, 
        params: Dict[str, str] = None, 
        data: Dict[str, str] = None
    ) -> Baseline:
        """
        Fires probe requests to model the target's behavior.
        """
        logger.info(f"Calibrating baseline for {url} (Samples: {self.samples})")
        
        responses: List[ResponseData] = []
        
        # 1. Acquisition Loop
        for i in range(self.samples):
            # We treat these as "clean" requests (no injection)
            resp = self.req_engine.send(url, method, params, data)
            
            # Critical: If connection fails during baseline, we cannot proceed.
            if resp.status_code == 0:
                logger.warning(f"Baseline probe {i+1} failed: {resp.text}")
                continue
                
            responses.append(resp)
        
        if not responses:
            raise RuntimeError("Failed to establish baseline: No successful connections.")

        # 2. Statistical Analysis
        return self._compute_statistics(responses, url, method)

    def _compute_statistics(self, responses: List[ResponseData], url: str, method: str) -> Baseline:
        """
        Converts raw responses into a statistical model.
        """
        # Status Code Consensus
        status_codes = [r.status_code for r in responses]
        primary_status = statistics.mode(status_codes)
        
        # Filter Outliers: Only consider responses that match the primary status code
        # If the server throws a random 500 error, we exclude it from our size/time averages.
        valid_responses = [r for r in responses if r.status_code == primary_status]
        
        if len(valid_responses) < 2:
            # Too much chaos to compute stdev
            logger.error("Target is extremely unstable (Status Code Flapping).")
            return self._create_unstable_baseline(responses[0], url, method)

        # Extract Metrics
        lengths = [r.content_length for r in valid_responses]
        times = [r.response_time for r in valid_responses]
        line_counts = [len(r.text.splitlines()) for r in valid_responses]

        # Calculate Mean & Standard Deviation
        # If stdev is 0 (perfectly static), we set a tiny epsilon to prevent DivisionByZero later.
        avg_len = statistics.mean(lengths)
        std_len = statistics.stdev(lengths) if len(lengths) > 1 else 0.0
        
        avg_time = statistics.mean(times)
        std_time = statistics.stdev(times) if len(times) > 1 else 0.0
        
        avg_lines = statistics.mean(line_counts)

        # Stability Scoring (Heuristic)
        # If size fluctuates by > 5% naturally, stability drops.
        size_variation = (std_len / avg_len) if avg_len > 0 else 0
        stability_score = max(0.0, 1.0 - (size_variation * 10)) # Penalize variation heavily

        # Pick a reference hash (Median length response)
        # We sort by length and pick the middle one as the "Standard" text body
        valid_responses.sort(key=lambda x: x.content_length)
        median_resp = valid_responses[len(valid_responses) // 2]

        return Baseline(
            url=url,
            method=method,
            status_code=primary_status,
            avg_content_length=avg_len,
            stdev_content_length=std_len,
            avg_response_time=avg_time,
            stdev_response_time=std_time,
            avg_line_count=avg_lines,
            reference_hash=median_resp.content_hash,
            is_stable=(stability_score > 0.8),
            stability_score=round(stability_score, 2)
        )

    def _create_unstable_baseline(self, resp: ResponseData, url: str, method: str) -> Baseline:
        """Fallback for chaotic targets."""
        return Baseline(
            url=url,
            method=method,
            status_code=resp.status_code,
            avg_content_length=float(resp.content_length),
            stdev_content_length=9999.9, # Massive tolerance
            avg_response_time=resp.response_time,
            stdev_response_time=9999.9,
            avg_line_count=float(len(resp.text.splitlines())),
            reference_hash=resp.content_hash,
            is_stable=False,
            stability_score=0.0
        )