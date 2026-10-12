"""
DNS-SHIELD Desktop Control Application.

A lightweight, native Windows desktop application for managing the local
DNS-SHIELD background service. Communicates over authenticated Named Pipe IPC.
Closing the UI does not affect background service protection.
"""

import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import tkinter as tk
from tkinter import messagebox, ttk

from local_ipc import NamedPipeClient
from service_health import HealthState

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("DNSShield.DesktopApp")


def get_ipc_secret_path() -> Path:
    program_data = Path(os.environ.get("PROGRAMDATA", Path.home() / "AppData" / "Local"))
    return program_data / "DNS-SHIELD" / "ipc.secret"


class DNSShieldApp(tk.Tk):
    """Native Windows Desktop Interface for DNS-SHIELD."""

    def __init__(self):
        super().__init__()

        self.title("DNS-SHIELD — Windows DNS Protection")
        self.geometry("960x650")
        self.minsize(800, 550)

        # Theme Colors (Modern Dark / Slate Security Palette)
        self.colors = {
            "bg": "#0f172a",          # Slate 900
            "card_bg": "#1e293b",     # Slate 800
            "sidebar_bg": "#090d16",  # Slate 950
            "fg": "#f8fafc",          # Slate 50
            "fg_muted": "#94a3b8",    # Slate 400
            "border": "#334155",      # Slate 700
            "accent": "#38bdf8",      # Sky 400
            "accent_hover": "#0284c7",# Sky 600
            "green": "#22c55e",       # Green 500
            "red": "#ef4444",         # Red 500
            "yellow": "#f59e0b",      # Amber 500
            "gray": "#64748b",        # Slate 500
        }
        self.configure(bg=self.colors["bg"])

        # Service IPC Client
        self.client: Optional[NamedPipeClient] = None
        self._init_ipc_client()

        # State Variables
        self.health_state = tk.StringVar(value="CHECKING...")
        self.health_detail = tk.StringVar(value="Connecting to local service...")
        self.search_filter = tk.StringVar(value="")
        self.auto_refresh_active = True
        self.last_events: List[Dict[str, Any]] = []

        self._configure_styles()
        self._build_ui()

        # Start periodic polling in background thread
        self._poll_thread = threading.Thread(target=self._background_poll_loop, daemon=True)
        self._poll_thread.start()

    def _init_ipc_client(self):
        secret_path = get_ipc_secret_path()
        if secret_path.exists():
            try:
                secret = secret_path.read_bytes().strip()
                self.client = NamedPipeClient(secret)
                logger.info("IPC client initialized with local secret.")
            except Exception as e:
                logger.warning(f"Failed to read IPC secret: {e}")
                self.client = None
        else:
            self.client = None

    def _configure_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Global style mappings
        style.configure(".", background=self.colors["bg"], foreground=self.colors["fg"], font=("Segoe UI", 10))
        style.configure("Card.TFrame", background=self.colors["card_bg"], relief="flat")
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground=self.colors["fg"], background=self.colors["bg"])
        style.configure("SubHeader.TLabel", font=("Segoe UI", 10), foreground=self.colors["fg_muted"], background=self.colors["bg"])

        style.configure("Status.TLabel", font=("Segoe UI", 13, "bold"), background=self.colors["card_bg"])
        style.configure("Detail.TLabel", font=("Segoe UI", 9), foreground=self.colors["fg_muted"], background=self.colors["card_bg"])

        # Modern Buttons
        style.configure(
            "Primary.TButton",
            font=("Segoe UI", 10, "bold"),
            background=self.colors["accent"],
            foreground="#0f172a",
            borderwidth=0,
            padding=6,
        )
        style.map("Primary.TButton", background=[("active", self.colors["accent_hover"])])

        style.configure(
            "Danger.TButton",
            font=("Segoe UI", 10, "bold"),
            background=self.colors["red"],
            foreground="#ffffff",
            borderwidth=0,
            padding=6,
        )

        style.configure(
            "Secondary.TButton",
            font=("Segoe UI", 9),
            background=self.colors["card_bg"],
            foreground=self.colors["fg"],
            borderwidth=1,
            padding=5,
        )

        # Tabs
        style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=self.colors["card_bg"], foreground=self.colors["fg_muted"], padding=[12, 6], font=("Segoe UI", 10))
        style.map("TNotebook.Tab", background=[("selected", self.colors["accent"])], foreground=[("selected", "#0f172a")])

        # Treeview (Logs & Rules table)
        style.configure(
            "Treeview",
            background=self.colors["card_bg"],
            foreground=self.colors["fg"],
            fieldbackground=self.colors["card_bg"],
            rowheight=26,
            font=("Segoe UI", 9),
        )
        style.map("Treeview", background=[("selected", "#334155")], foreground=[("selected", "#ffffff")])
        style.configure("Treeview.Heading", background=self.colors["sidebar_bg"], foreground=self.colors["accent"], font=("Segoe UI", 9, "bold"))

    def _build_ui(self):
        # 1. Top Bar / Header
        top_bar = tk.Frame(self, bg=self.colors["sidebar_bg"], height=70, padx=20, pady=10)
        top_bar.pack(fill=tk.X, side=tk.TOP)

        title_lbl = tk.Label(top_bar, text="DNS-SHIELD", font=("Segoe UI", 18, "bold"), fg=self.colors["accent"], bg=self.colors["sidebar_bg"])
        title_lbl.pack(side=tk.LEFT)

        sub_lbl = tk.Label(top_bar, text="Windows 11 Native DNS Protection", font=("Segoe UI", 10), fg=self.colors["fg_muted"], bg=self.colors["sidebar_bg"])
        sub_lbl.pack(side=tk.LEFT, padx=12, pady=(6, 0))

        # Recovery Button on Header
        recovery_btn = ttk.Button(top_bar, text="Restore Default DNS", style="Secondary.TButton", command=self._action_restore_network)
        recovery_btn.pack(side=tk.RIGHT, padx=5)

        # 2. Status Banner Card
        banner_frame = tk.Frame(self, bg=self.colors["card_bg"], bd=1, relief=tk.SOLID, padx=20, pady=15)
        banner_frame.pack(fill=tk.X, padx=20, pady=(15, 10))

        status_left = tk.Frame(banner_frame, bg=self.colors["card_bg"])
        status_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.lbl_status_badge = tk.Label(
            status_left,
            textvariable=self.health_state,
            font=("Segoe UI", 15, "bold"),
            fg=self.colors["yellow"],
            bg=self.colors["card_bg"]
        )
        self.lbl_status_badge.pack(anchor=tk.W)

        self.lbl_detail = tk.Label(
            status_left,
            textvariable=self.health_detail,
            font=("Segoe UI", 10),
            fg=self.colors["fg_muted"],
            bg=self.colors["card_bg"]
        )
        self.lbl_detail.pack(anchor=tk.W, pady=(2, 0))

        # Action Buttons on Banner
        self.btn_toggle_protection = ttk.Button(
            banner_frame,
            text="Enable Protection",
            style="Primary.TButton",
            command=self._action_toggle_protection
        )
        self.btn_toggle_protection.pack(side=tk.RIGHT, padx=5)

        # 3. Main Notebook (Tabs)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))

        # Tab 1: Live DNS Query Logs
        self.tab_logs = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(self.tab_logs, text="Live Activity (Events)")
        self._build_logs_tab()

        # Tab 2: Policy & Custom Rules
        self.tab_rules = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(self.tab_rules, text="Rules & Allowlist")
        self._build_rules_tab()

        # Tab 3: Diagnostics & Health
        self.tab_diag = tk.Frame(self.notebook, bg=self.colors["bg"])
        self.notebook.add(self.tab_diag, text="Diagnostics & System")
        self._build_diagnostics_tab()

    def _build_logs_tab(self):
        # Search & Filter controls
        filter_bar = tk.Frame(self.tab_logs, bg=self.colors["bg"], pady=8)
        filter_bar.pack(fill=tk.X)

        lbl_search = tk.Label(filter_bar, text="Filter by Domain:", fg=self.colors["fg_muted"], bg=self.colors["bg"])
        lbl_search.pack(side=tk.LEFT)

        entry_search = tk.Entry(filter_bar, textvariable=self.search_filter, bg=self.colors["card_bg"], fg=self.colors["fg"], insertbackground=self.colors["fg"], width=30)
        entry_search.pack(side=tk.LEFT, padx=8)
        entry_search.bind("<KeyRelease>", lambda _: self._render_events())

        btn_clear = ttk.Button(filter_bar, text="Clear", style="Secondary.TButton", command=lambda: (self.search_filter.set(""), self._render_events()))
        btn_clear.pack(side=tk.LEFT)

        btn_refresh = ttk.Button(filter_bar, text="Refresh Now", style="Secondary.TButton", command=self._poll_status_and_events)
        btn_refresh.pack(side=tk.RIGHT)

        # Table of Events
        columns = ("time", "decision", "domain", "type", "rule", "reason")
        self.tree_events = ttk.Treeview(self.tab_logs, columns=columns, show="headings", selectmode="browse")

        self.tree_events.heading("time", text="Timestamp")
        self.tree_events.heading("decision", text="Verdict")
        self.tree_events.heading("domain", text="Domain Name")
        self.tree_events.heading("type", text="Type")
        self.tree_events.heading("rule", text="Rule")
        self.tree_events.heading("reason", text="Reason / Details")

        self.tree_events.column("time", width=120, anchor=tk.CENTER)
        self.tree_events.column("decision", width=90, anchor=tk.CENTER)
        self.tree_events.column("domain", width=220, anchor=tk.W)
        self.tree_events.column("type", width=55, anchor=tk.CENTER)
        self.tree_events.column("rule", width=130, anchor=tk.W)
        self.tree_events.column("reason", width=300, anchor=tk.W)

        # Scrollbar
        scroll = ttk.Scrollbar(self.tab_logs, orient=tk.VERTICAL, command=self.tree_events.yview)
        self.tree_events.configure(yscrollcommand=scroll.set)

        self.tree_events.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Tags for colored rows
        self.tree_events.tag_configure("ALLOW", foreground="#4ade80")  # Green
        self.tree_events.tag_configure("BLOCK", foreground="#f87171")  # Red

    def _build_rules_tab(self):
        container = tk.Frame(self.tab_rules, bg=self.colors["bg"], pady=10)
        container.pack(fill=tk.BOTH, expand=True)

        # Left Column: Custom Block Rules
        left_col = tk.Frame(container, bg=self.colors["card_bg"], padx=12, pady=12, bd=1, relief=tk.SOLID)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        tk.Label(left_col, text="Administrator Block Rules", font=("Segoe UI", 11, "bold"), fg=self.colors["accent"], bg=self.colors["card_bg"]).pack(anchor=tk.W)
        tk.Label(left_col, text="Queries matching these domains are denied with REFUSED.", font=("Segoe UI", 9), fg=self.colors["fg_muted"], bg=self.colors["card_bg"]).pack(anchor=tk.W, pady=(0, 8))

        add_frame_block = tk.Frame(left_col, bg=self.colors["card_bg"])
        add_frame_block.pack(fill=tk.X, pady=4)
        self.entry_block_domain = tk.Entry(add_frame_block, bg=self.colors["bg"], fg=self.colors["fg"], insertbackground=self.colors["fg"])
        self.entry_block_domain.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(add_frame_block, text="Add Block", style="Danger.TButton", command=self._action_add_block_rule).pack(side=tk.RIGHT)

        self.tree_blocks = ttk.Treeview(left_col, columns=("domain", "type", "reason"), show="headings", height=10)
        self.tree_blocks.heading("domain", text="Domain")
        self.tree_blocks.heading("type", text="Scope")
        self.tree_blocks.heading("reason", text="Reason")
        self.tree_blocks.column("domain", width=140)
        self.tree_blocks.column("type", width=70)
        self.tree_blocks.column("reason", width=140)
        self.tree_blocks.pack(fill=tk.BOTH, expand=True, pady=8)

        ttk.Button(left_col, text="Remove Selected Rule", style="Secondary.TButton", command=self._action_delete_block_rule).pack(anchor=tk.E)

        # Right Column: Allowlist Exceptions
        right_col = tk.Frame(container, bg=self.colors["card_bg"], padx=12, pady=12, bd=1, relief=tk.SOLID)
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6, 0))

        tk.Label(right_col, text="Allowlist Exemptions", font=("Segoe UI", 11, "bold"), fg=self.colors["green"], bg=self.colors["card_bg"]).pack(anchor=tk.W)
        tk.Label(right_col, text="Overrides threat blocklists and custom blocks.", font=("Segoe UI", 9), fg=self.colors["fg_muted"], bg=self.colors["card_bg"]).pack(anchor=tk.W, pady=(0, 8))

        add_frame_allow = tk.Frame(right_col, bg=self.colors["card_bg"])
        add_frame_allow.pack(fill=tk.X, pady=4)
        self.entry_allow_domain = tk.Entry(add_frame_allow, bg=self.colors["bg"], fg=self.colors["fg"], insertbackground=self.colors["fg"])
        self.entry_allow_domain.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        ttk.Button(add_frame_allow, text="Add Exemption", style="Primary.TButton", command=self._action_add_allowlist_rule).pack(side=tk.RIGHT)

        self.tree_allow = ttk.Treeview(right_col, columns=("domain", "type", "reason"), show="headings", height=10)
        self.tree_allow.heading("domain", text="Domain")
        self.tree_allow.heading("type", text="Scope")
        self.tree_allow.heading("reason", text="Reason")
        self.tree_allow.column("domain", width=140)
        self.tree_allow.column("type", width=70)
        self.tree_allow.column("reason", width=140)
        self.tree_allow.pack(fill=tk.BOTH, expand=True, pady=8)

        ttk.Button(right_col, text="Remove Selected Exemption", style="Secondary.TButton", command=self._action_delete_allowlist_rule).pack(anchor=tk.E)

    def _build_diagnostics_tab(self):
        diag_frame = tk.Frame(self.tab_diag, bg=self.colors["card_bg"], padx=15, pady=15)
        diag_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        header = tk.Frame(diag_frame, bg=self.colors["card_bg"])
        header.pack(fill=tk.X, pady=(0, 10))
        tk.Label(header, text="Service Health & Diagnostic Details", font=("Segoe UI", 12, "bold"), fg=self.colors["accent"], bg=self.colors["card_bg"]).pack(side=tk.LEFT)
        ttk.Button(header, text="Export Redacted Diagnostics", style="Primary.TButton", command=self._action_export_diagnostics).pack(side=tk.RIGHT)

        self.txt_diagnostics = tk.Text(diag_frame, bg=self.colors["bg"], fg=self.colors["fg"], font=("Consolas", 10), bd=1, relief=tk.SOLID, padx=10, pady=10)
        self.txt_diagnostics.pack(fill=tk.BOTH, expand=True)

    # --- Communication & Polling ---

    def _background_poll_loop(self):
        while self.auto_refresh_active:
            try:
                self._poll_status_and_events()
            except Exception as e:
                logger.debug(f"Poll loop exception: {e}")
            time.sleep(2.0)

    def _poll_status_and_events(self):
        if not self.client:
            self._init_ipc_client()

        if not self.client:
            self.after(0, self._set_offline_state, "IPC secret file not found. Ensure DNS-SHIELD service is installed.")
            return

        resp = self.client.call("get_status")
        if not resp.get("ok"):
            self.after(0, self._set_offline_state, f"Cannot reach background service: {resp.get('error')}")
            return

        status = resp["result"]
        self.after(0, self._update_status_ui, status)

        # Fetch recent events
        ev_resp = self.client.call("get_events", {"limit": 100})
        if ev_resp.get("ok"):
            self.last_events = ev_resp["result"]
            self.after(0, self._render_events)

        # Refresh rules periodically
        rules_resp = self.client.call("get_rules")
        if rules_resp.get("ok"):
            self.after(0, self._render_rules, rules_resp["result"])

    def _set_offline_state(self, detail_msg: str):
        self.health_state.set("SERVICE OFFLINE")
        self.health_detail.set(detail_msg)
        self.lbl_status_badge.config(fg=self.colors["red"])
        self.btn_toggle_protection.config(text="Service Not Running", state=tk.DISABLED)

    def _update_status_ui(self, status: Dict[str, Any]):
        state = status.get("state", "UNKNOWN")
        detail = status.get("detail", "")

        self.health_state.set(state)
        self.health_detail.set(detail)

        if state == "PROTECTED":
            self.lbl_status_badge.config(fg=self.colors["green"])
            self.btn_toggle_protection.config(text="Disable Protection", state=tk.NORMAL)
        elif state == "DEGRADED":
            self.lbl_status_badge.config(fg=self.colors["yellow"])
            self.btn_toggle_protection.config(text="Re-Enable Protection", state=tk.NORMAL)
        elif state == "DISABLED":
            self.lbl_status_badge.config(fg=self.colors["gray"])
            self.btn_toggle_protection.config(text="Enable Protection", state=tk.NORMAL)
        else:
            self.lbl_status_badge.config(fg=self.colors["red"])
            self.btn_toggle_protection.config(text="Resolve Error", state=tk.NORMAL)

    def _render_events(self):
        query = self.search_filter.get().strip().lower()
        self.tree_events.delete(*self.tree_events.get_children())

        for ev in self.last_events:
            domain = ev.get("domain", "")
            if query and query not in domain:
                continue

            ts = time.strftime("%H:%M:%S", time.localtime(ev.get("timestamp", time.time())))
            decision = ev.get("decision", "ALLOW")
            qtype = ev.get("qtype", "A")
            rule = ev.get("matched_rule", "") or ev.get("decision_type", "")
            reason = ev.get("reason", "")

            self.tree_events.insert(
                "",
                tk.END,
                values=(ts, decision, domain, qtype, rule, reason),
                tags=(decision,)
            )

    def _render_rules(self, data: Dict[str, Any]):
        # Custom rules
        self.tree_blocks.delete(*self.tree_blocks.get_children())
        for r in data.get("custom_rules", []):
            self.tree_blocks.insert("", tk.END, values=(r.get("domain"), r.get("rule_type"), r.get("reason")), iid=f"rule_{r.get('id')}")

        # Allowlist
        self.tree_allow.delete(*self.tree_allow.get_children())
        for a in data.get("allowlist", []):
            self.tree_allow.insert("", tk.END, values=(a.get("domain"), a.get("rule_type"), a.get("reason")), iid=f"allow_{a.get('id')}")

    # --- Actions ---

    def _action_toggle_protection(self):
        if not self.client:
            messagebox.showerror("Error", "Service IPC connection is not available.")
            return

        current_state = self.health_state.get()
        new_enabled = (current_state != "PROTECTED")

        resp = self.client.call("set_enabled", {"enabled": new_enabled})
        if resp.get("ok"):
            self._poll_status_and_events()
        else:
            messagebox.showerror("Action Failed", f"Could not change protection state: {resp.get('error')}")

    def _action_restore_network(self):
        confirm = messagebox.askyesno(
            "Restore Network Configuration",
            "This will restore original DNS server addresses (e.g. DHCP) on all active adapters.\n\nProceed with emergency restoration?"
        )
        if not confirm:
            return

        if not self.client:
            # Fallback to local network_manager
            from network_manager import NetworkManager
            nm = NetworkManager()
            res = nm.restore_dns()
            messagebox.showinfo("Result", f"Restoration result: {res}")
            return

        resp = self.client.call("restore_network")
        if resp.get("ok"):
            messagebox.showinfo("Success", "Original network adapter DNS settings successfully restored.")
            self._poll_status_and_events()
        else:
            messagebox.showerror("Error", f"Restoration failed: {resp.get('error')}")

    def _action_add_block_rule(self):
        domain = self.entry_block_domain.get().strip().lower()
        if not domain:
            return
        if not self.client:
            return
        resp = self.client.call("add_rule", {"domain": domain, "rule_type": "subdomain", "reason": "User Block Rule"})
        if resp.get("ok"):
            self.entry_block_domain.delete(0, tk.END)
            self._poll_status_and_events()
        else:
            messagebox.showerror("Error", resp.get("error"))

    def _action_delete_block_rule(self):
        sel = self.tree_blocks.selection()
        if not sel or not self.client:
            return
        item_id = sel[0]
        if item_id.startswith("rule_"):
            db_id = int(item_id.split("_")[1])
            self.client.call("delete_rule", {"id": db_id})
            self._poll_status_and_events()

    def _action_add_allowlist_rule(self):
        domain = self.entry_allow_domain.get().strip().lower()
        if not domain:
            return
        if not self.client:
            return
        resp = self.client.call("add_allowlist", {"domain": domain, "rule_type": "exact", "reason": "User Exemption"})
        if resp.get("ok"):
            self.entry_allow_domain.delete(0, tk.END)
            self._poll_status_and_events()
        else:
            messagebox.showerror("Error", resp.get("error"))

    def _action_delete_allowlist_rule(self):
        sel = self.tree_allow.selection()
        if not sel or not self.client:
            return
        item_id = sel[0]
        if item_id.startswith("allow_"):
            db_id = int(item_id.split("_")[1])
            self.client.call("delete_allowlist", {"id": db_id})
            self._poll_status_and_events()

    def _action_export_diagnostics(self):
        if not self.client:
            messagebox.showerror("Error", "Service not connected.")
            return
        resp = self.client.call("diagnostics")
        if not resp.get("ok"):
            messagebox.showerror("Error", resp.get("error"))
            return

        diag_data = resp["result"]
        diag_text = json.dumps(diag_data, indent=2)
        self.txt_diagnostics.delete("1.0", tk.END)
        self.txt_diagnostics.insert(tk.END, diag_text)
        messagebox.showinfo("Diagnostics Export", "Diagnostics generated below with API keys and secrets redacted.")


def main():
    app = DNSShieldApp()
    app.mainloop()


if __name__ == "__main__":
    main()
