import json
import hashlib
import base64
import urllib.parse
from pathlib import Path
from typing import Generator, Set, List, Optional, Dict, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging

# Setup module-level logger
logger = logging.getLogger("SignalFuzz.Payloads")

class MutationType(Enum):
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    BASE64 = "base64"
    HEX = "hex"

@dataclass(slots=True, frozen=True)
class Payload:
    """
    Immutable, memory-optimized payload structure.
    Using __slots__ prevents the creation of a dynamic __dict__, saving RAM.
    """
    content: str
    category: str = "generic"
    tags: tuple = field(default_factory=tuple)
    
    @property
    def identifier(self) -> str:
        """Generates a deterministic hash for deduplication."""
        return hashlib.md5(self.content.encode()).hexdigest()

class PayloadEngine:
    """
    Professional-grade payload orchestration.
    Handles streaming, mutation, and validation without memory bloat.
    """
    
    def __init__(self, filepath: str, mutations: List[MutationType] = None):
        self.filepath = Path(filepath)
        self.mutations = mutations or [MutationType.NONE]
        self.seen_hashes: Set[str] = set()
        self._validate_source()

    def _validate_source(self):
        if not self.filepath.exists():
            raise FileNotFoundError(f"Payload artifact missing: {self.filepath}")
        if not self.filepath.is_file():
            raise IsADirectoryError(f"Target is not a file: {self.filepath}")

    def stream(self) -> Generator[Payload, None, None]:
        """
        The Core Pipeline.
        Yields payloads one by one. Zero memory footprint for the dataset.
        """
        logger.debug(f"Streaming payloads from {self.filepath.name}")
        
        # Select parser strategy based on extension
        parser = self._get_parser()
        
        for raw_payload_obj in parser():
            # 1. Validation Logic
            if not self._is_valid(raw_payload_obj):
                continue

            # 2. Mutation Logic (Expansion)
            for mutation in self.mutations:
                mutated_content = self._apply_mutation(raw_payload_obj.content, mutation)
                
                # 3. Deduplication Logic (Global)
                # We hash the mutated content to ensure uniqueness across all transforms
                payload_hash = hashlib.sha1(mutated_content.encode()).hexdigest()
                
                if payload_hash in self.seen_hashes:
                    continue
                
                self.seen_hashes.add(payload_hash)
                
                yield Payload(
                    content=mutated_content,
                    category=raw_payload_obj.category,
                    tags=raw_payload_obj.tags
                )

    def _get_parser(self) -> Callable:
        """Strategy pattern to select the correct file parser."""
        ext = self.filepath.suffix.lower()
        if ext == '.json':
            return self._parse_json
        elif ext in ['.txt', '.csv', '.fuzz']:
            return self._parse_txt
        else:
            logger.warning(f"Unknown extension {ext}, defaulting to TXT parser.")
            return self._parse_txt

    def _parse_txt(self) -> Generator[Payload, None, None]:
        """High-performance line reader."""
        try:
            with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    clean_line = line.strip()
                    if clean_line and not clean_line.startswith('#'):
                        yield Payload(content=clean_line, category="txt_import")
        except IOError as e:
            logger.error(f"IO Failure during stream: {e}")

    def _parse_json(self) -> Generator[Payload, None, None]:
        """
        Streaming JSON parser. 
        Expects list of dicts: [{"payload": "...", "category": "..."}]
        """
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                # Note: For massive JSON files (GBs), we would use ijson here.
                # Standard json.load is fine for up to ~500MB.
                data = json.load(f)
                
            if not isinstance(data, list):
                logger.error("JSON payload file must be a list of objects.")
                return

            for entry in data:
                if "payload" in entry:
                    yield Payload(
                        content=str(entry["payload"]),
                        category=entry.get("category", "json_import"),
                        tags=tuple(entry.get("tags", []))
                    )
        except json.JSONDecodeError as e:
            logger.error(f"Malformed JSON: {e}")

    def _is_valid(self, payload: Payload) -> bool:
        """Strict validation rules."""
        if not payload.content:
            return False
        if len(payload.content) > 10000: # Sanity check for massive buffers
            logger.warning(f"Skipping oversized payload ({len(payload.content)} bytes)")
            return False
        return True

    @staticmethod
    def _apply_mutation(content: str, mutation: MutationType) -> str:
        """
        Applies encoding transformations.
        This is critical for bypassing WAFs.
        """
        try:
            if mutation == MutationType.NONE:
                return content
            elif mutation == MutationType.URL:
                return urllib.parse.quote(content)
            elif mutation == MutationType.DOUBLE_URL:
                return urllib.parse.quote(urllib.parse.quote(content))
            elif mutation == MutationType.BASE64:
                return base64.b64encode(content.encode()).decode()
            elif mutation == MutationType.HEX:
                return "".join([hex(ord(c))[2:] for c in content])
        except Exception:
            return content # Fallback to original on failure
        return content