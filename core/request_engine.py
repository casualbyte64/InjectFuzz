import time
import hashlib
import requests
import urllib3
from typing import Dict, Any, Optional
from dataclasses import dataclass
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 1. Suppress Unsafe SSL Warnings (Standard for offensive tools)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass(slots=True)
class ResponseData:
    """
    Memory-optimized data structure for responses.
    slots=True reduces memory footprint per instance.
    """
    status_code: int
    response_time: float
    content_length: int
    content_hash: str
    text: str  # We will truncate this if too large
    url: str

class RequestEngine:
    """
    Professional Transport Layer.
    - Non-destructive parameter merging
    - Proxy-aware
    - Unsafe SSL support
    - Automatic response truncation
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_retries: int = 3,
        proxy: Optional[str] = None,
        user_agent: str = "SignalFuzz/1.0 (Safe Research)",
        verify_ssl: bool = False
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Configure Proxy (e.g., http://127.0.0.1:8080 for Burp)
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        
        self.headers = {
            "User-Agent": user_agent,
            "Connection": "keep-alive",
            "Cache-Control": "no-cache"
        }
        
        self.session = self._init_session(max_retries)

    def _init_session(self, max_retries: int) -> requests.Session:
        session = requests.Session()
        
        # High-performance Retry Strategy
        retry = Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            backoff_factor=0.2, # Fast retry
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=20, # Increased pool size for threading
            pool_maxsize=20
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.proxies.update(self.proxies or {})
        session.headers.update(self.headers)
        
        return session

    def send(
        self, 
        url: str, 
        method: str, 
        params: Dict[str, str] = None, 
        data: Dict[str, str] = None
    ) -> ResponseData:
        """
        Executes request. Params/Data must be fully constructed BEFORE calling this.
        This ensures the Engine is generic and doesn't guess how to merge params.
        """
        try:
            start_time = time.perf_counter()
            
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False # Important: Don't follow redirects blindly in fuzzing
            )
            
            # High-Res Timing
            elapsed = time.perf_counter() - start_time
            
            # Content Safety Logic
            text_content = response.text
            
            # Optimization: If body is huge, truncate stored text but keep hash valid
            if len(text_content) > 100_000: # 100KB limit for RAM safety
                stored_text = text_content[:100_000] + "...[TRUNCATED]"
            else:
                stored_text = text_content

            return ResponseData(
                status_code=response.status_code,
                response_time=round(elapsed, 4),
                content_length=len(response.content), # Actual byte length
                content_hash=hashlib.md5(response.content).hexdigest(),
                text=stored_text,
                url=response.url
            )

        except requests.RequestException as e:
            # Return a "Dead" response object instead of crashing
            # This allows the fuzzer to log the error and keep moving
            return ResponseData(
                status_code=0,
                response_time=0.0,
                content_length=0,
                content_hash="error",
                text=str(e),
                url=url
            )