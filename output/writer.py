import json
import os
import time
import uuid
import sys
import re  # <--- Added re for stricter regex replacement
from datetime import datetime, timezone
from typing import Dict, Any, List

class OutputWriter:
    """
    Professional Audit-Grade Reporter.
    """

    def __init__(self, target_url: str, config: Dict[str, Any], output_dir: str = "reports"):
        self.start_time = time.time()
        self.output_dir = output_dir
        self.session_id = str(uuid.uuid4())[:8]
        
        # Ensure directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        # -------------------------------------------------------------------------
        # FIX IS HERE: STRICT WINDOWS-SAFE SANITIZATION
        # -------------------------------------------------------------------------
        # We use regex to replace ANYTHING that is not a letter, number, dot, or dash with an underscore.
        # This removes ?, :, /, \, *, <, >, |, " automatically.
        clean_name = re.sub(r'[^a-zA-Z0-9\.\-]', '_', target_url)
        
        # Limit length to 50 chars to avoid "Path too long" errors
        sanitized_target = clean_name[:50]
        
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M")
        self.filename = os.path.join(self.output_dir, f"{timestamp}_{sanitized_target}_{self.session_id}.json")

        # Internal State
        self.file_handle = None
        self.first_finding = True
        self.finding_count = 0

        # Initialize the Report Structure
        self._initialize_report(target_url, config)

    def _initialize_report(self, target_url: str, config: Dict[str, Any]):
        """
        Opens the file and writes the Metadata and Timeline header.
        """
        meta = {
            "tool": "SignalFuzz Pro",
            "version": "1.0.0",
            "session_id": self.session_id,
            "timestamp_start": datetime.now(timezone.utc).isoformat(),
            "target": target_url,
            "configuration": config,
            "system": {
                "platform": sys.platform,
                "python": sys.version.split()[0]
            }
        }

        try:
            self.file_handle = open(self.filename, 'w', encoding='utf-8')
            
            # 1. Write Meta
            self.file_handle.write('{\n  "meta": ')
            json.dump(meta, self.file_handle, indent=4)
            
            # 2. Start Timeline
            self.file_handle.write(',\n  "timeline": [\n')
            self._write_timeline_event("scan_started", {"timestamp": time.time()})
            
            # 3. Close Timeline and Start Findings
            self.file_handle.write('\n  ],\n  "findings": [\n')
            
            self.file_handle.flush()
            print(f"[*] Report initialized: {self.filename}")
            
        except IOError as e:
            # If it fails now, it's a permission issue, not a filename issue
            print(f"[!] CRITICAL: Cannot write to report file: {e}")
            sys.exit(1)

    def _write_timeline_event(self, event_name: str, data: Dict[str, Any]):
        event = {
            "event": event_name,
            "time": datetime.now(timezone.utc).isoformat(),
            "data": data
        }
        json.dump(event, self.file_handle)

    def write_finding(self, finding_data: Dict[str, Any]):
        try:
            if not self.first_finding:
                self.file_handle.write(',\n')
            
            self.file_handle.write('    ')
            json.dump(finding_data, self.file_handle)
            
            self.first_finding = False
            self.finding_count += 1
            self.file_handle.flush()
            
        except IOError as e:
            print(f"[!] Write Error: {e}")

    def finalize(self):
        if self.file_handle and not self.file_handle.closed:
            duration = time.time() - self.start_time
            
            self.file_handle.write('\n  ],\n')
            
            summary = {
                "scan_duration_seconds": round(duration, 2),
                "total_findings": self.finding_count,
                "timestamp_end": datetime.now(timezone.utc).isoformat(),
                "status": "completed"
            }
            
            self.file_handle.write('  "summary": ')
            json.dump(summary, self.file_handle, indent=4)
            
            self.file_handle.write('\n}')
            self.file_handle.close()
            print(f"[*] Scan finalized. Output saved to {self.filename}")

    def __del__(self):
        if self.file_handle and not self.file_handle.closed:
            try:
                self.file_handle.write('\n  ]\n}')
                self.file_handle.close()
            except:
                pass