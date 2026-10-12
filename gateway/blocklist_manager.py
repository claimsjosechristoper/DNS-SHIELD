"""
Atomic Blocklist Manager with Validation and Last-Known-Good Fail-Safe.
Parses domain lists / hosts files, validates domain syntax, and replaces
in-memory routing structures atomically while retaining previous safe state on update failures.
"""

import os
import time
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, List, Set, Optional, Tuple
from gateway.normalization import normalize_domain
from gateway.matcher import get_domain_candidates
from gateway.db import get_db

logger = logging.getLogger("DNSShield.BlocklistManager")

class BlocklistManager:
    def __init__(self):
        # In-memory atomically replaced mapping: domain -> {"source_id": int, "source_name": str, "category": str}
        self.active_blocklist: Dict[str, Dict[str, Any]] = {}
        # Per-source cached entries for rollback / retain last known good
        self.last_known_good: Dict[int, Dict[str, Dict[str, Any]]] = {}

    def parse_and_validate_content(self, text: str, source_info: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
        """
        Parses blocklist lines (plain domain or hosts file format), validates domains,
        and returns {domain: metadata} or an error string if invalid.
        """
        valid_entries: Dict[str, Dict[str, Any]] = {}
        lines = text.splitlines()

        for line in lines:
            line = line.strip()
            # Ignore empty lines and comments
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            # Strip inline comment
            if "#" in line:
                line = line.split("#", 1)[0].strip()

            parts = line.split()
            if not parts:
                continue

            # Handle hosts format (e.g. '0.0.0.0 example.com' or '127.0.0.1 example.com')
            raw_domain = parts[1] if (len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1")) else parts[0]

            normalized, is_valid, err = normalize_domain(raw_domain)
            if is_valid and normalized and normalized != ".":
                valid_entries[normalized] = {
                    "source_id": source_info["id"],
                    "source_name": source_info["name"],
                    "category": source_info["category"]
                }

        if not valid_entries:
            return {}, "Blocklist content contained 0 valid domain entries or was malformed"

        return valid_entries, None

    def fetch_source_content(self, url_or_path: str) -> Tuple[Optional[str], Optional[str]]:
        """Fetches blocklist content from local filesystem or HTTP/S URL."""
        if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
            try:
                req = urllib.request.Request(
                    url_or_path,
                    headers={"User-Agent": "DNS-Security-Gateway/1.0"}
                )
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    if resp.status != 200:
                        return None, f"HTTP error {resp.status}"
                    content = resp.read().decode("utf-8", errors="ignore")
                    return content, None
            except Exception as e:
                return None, f"Network fetch failed: {str(e)}"
        else:
            # Local file
            if not os.path.exists(url_or_path):
                return None, f"Local file not found: {url_or_path}"
            try:
                with open(url_or_path, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read(), None
            except Exception as e:
                return None, f"File read error: {str(e)}"

    def sync_source(self, source_id: int, db_path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Synchronizes an individual source. Validates content and updates atomically.
        If validation or fetch fails, retains last known good list.
        """
        conn = get_db(db_path)
        cur = conn.cursor()
        cur.execute("SELECT id, name, url_or_path, category, enabled FROM blocklist_sources WHERE id = ?", (source_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return False, f"Source ID {source_id} not found"

        source_info = dict(row)
        content, fetch_err = self.fetch_source_content(source_info["url_or_path"])

        if fetch_err:
            logger.warning(f"Failed to fetch blocklist '{source_info['name']}': {fetch_err}. Retaining last known good list.")
            cur.execute("""
                UPDATE blocklist_sources 
                SET last_status = 'ERROR', last_error = ? 
                WHERE id = ?
            """, (fetch_err, source_id))
            conn.commit()
            conn.close()
            return False, fetch_err

        new_entries, val_err = self.parse_and_validate_content(content, source_info)
        if val_err:
            logger.warning(f"Validation failed for blocklist '{source_info['name']}': {val_err}. Retaining last known good list.")
            cur.execute("""
                UPDATE blocklist_sources 
                SET last_status = 'ERROR', last_error = ? 
                WHERE id = ?
            """, (val_err, source_id))
            conn.commit()
            conn.close()
            return False, val_err

        # Successful validation! Atomically update memory and database
        self.last_known_good[source_id] = new_entries
        
        # Update database entries
        cur.execute("DELETE FROM blocklist_entries WHERE source_id = ?", (source_id,))
        entries_to_insert = [(source_id, d) for d in new_entries.keys()]
        cur.executemany("INSERT INTO blocklist_entries (source_id, domain) VALUES (?, ?)", entries_to_insert)

        now = time.time()
        cur.execute("""
            UPDATE blocklist_sources 
            SET entry_count = ?, last_updated = ?, last_status = 'OK', last_error = NULL 
            WHERE id = ?
        """, (len(new_entries), now, source_id))
        conn.commit()
        conn.close()

        # Recompile complete active blocklist atomically
        self.rebuild_active_blocklist()
        logger.info(f"Blocklist '{source_info['name']}' successfully updated with {len(new_entries)} valid domains.")
        return True, f"Successfully loaded {len(new_entries)} domains."

    def sync_all_sources(self, db_path: Optional[str] = None) -> Dict[str, Any]:
        """Synchronizes all enabled blocklist sources."""
        conn = get_db(db_path)
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM blocklist_sources WHERE enabled = 1")
        sources = [dict(r) for r in cur.fetchall()]
        conn.close()

        results = {}
        for s in sources:
            ok, msg = self.sync_source(s["id"], db_path)
            results[s["name"]] = {"success": ok, "message": msg}

        return results

    def load_from_db(self, db_path: Optional[str] = None):
        """Loads cached entries directly from database on startup."""
        conn = get_db(db_path)
        cur = conn.cursor()
        cur.execute("""
            SELECT s.id, s.name, s.category, e.domain 
            FROM blocklist_entries e
            JOIN blocklist_sources s ON e.source_id = s.id
            WHERE s.enabled = 1
        """)
        
        reloaded: Dict[int, Dict[str, Dict[str, Any]]] = {}
        for r in cur.fetchall():
            s_id = r["id"]
            if s_id not in reloaded:
                reloaded[s_id] = {}
            reloaded[s_id][r["domain"]] = {
                "source_id": s_id,
                "source_name": r["name"],
                "category": r["category"]
            }
        conn.close()

        self.last_known_good = reloaded
        self.rebuild_active_blocklist()
        
        # If DB had no entries yet, trigger initial sync
        if not self.active_blocklist:
            self.sync_all_sources(db_path)

    def rebuild_active_blocklist(self):
        """Atomically swaps the active blocklist dictionary reference."""
        merged: Dict[str, Dict[str, Any]] = {}
        for s_id, entries in self.last_known_good.items():
            merged.update(entries)
        # Atomic reference swap in Python
        self.active_blocklist = merged

    def match(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Checks domain and parent domain candidates against active threat blocklist.
        Returns match dict if blocked, or None.
        """
        candidates = get_domain_candidates(domain)
        for cand in candidates:
            if cand in self.active_blocklist:
                info = self.active_blocklist[cand]
                return {
                    "matched": True,
                    "matched_domain": cand,
                    "source_name": info["source_name"],
                    "category": info["category"],
                    "source_id": info["source_id"]
                }
        return None
