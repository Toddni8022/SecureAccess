"""
SecureAccess - User Access Management Platform
A professional desktop application for security teams to manage
user identities, roles, access requests, and compliance reviews.

Author: Todd Nicholas
"""

import customtkinter as ctk
from tkinter import messagebox, filedialog
import tkinter as tk
from datetime import datetime, timedelta
import csv
import json
import os
import sys

from database import Database
from connectors import ConnectorManager, CONNECTORS

# ── Theme & Constants ──
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLORS = {
    'bg_dark': '#1a1a2e',
    'bg_card': '#16213e',
    'bg_sidebar': '#0f3460',
    'accent': '#e94560',
    'accent_green': '#00b894',
    'accent_yellow': '#fdcb6e',
    'accent_orange': '#e17055',
    'accent_blue': '#0984e3',
    'text': '#ffffff',
    'text_dim': '#a0a0b0',
    'critical': '#e74c3c',
    'high': '#e67e22',
    'medium': '#f1c40f',
    'low': '#2ecc71',
}

RISK_COLORS = {
    'critical': COLORS['critical'],
    'high': COLORS['high'],
    'medium': COLORS['medium'],
    'low': COLORS['low'],
}


class SecureAccessApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.db = Database()
        self.connector_mgr = ConnectorManager(self.db)
        self.title("SecureAccess — User Access Management")
        self.geometry("1400x850")
        self.minsize(1100, 700)

        # Configure grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_area()
        self.show_dashboard()

    # ══════════════════════════════════════════════
    #  SIDEBAR
    # ══════════════════════════════════════════════
    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color=COLORS['bg_sidebar'])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # Logo / Title
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.pack(fill="x", padx=15, pady=(20, 5))
        ctk.CTkLabel(logo_frame, text="🛡️", font=ctk.CTkFont(size=32)).pack()
        ctk.CTkLabel(logo_frame, text="SecureAccess", font=ctk.CTkFont(size=20, weight="bold")).pack()
        ctk.CTkLabel(logo_frame, text="Access Management", font=ctk.CTkFont(size=11), text_color=COLORS['text_dim']).pack()

        ctk.CTkFrame(self.sidebar, height=2, fg_color=COLORS['text_dim']).pack(fill="x", padx=20, pady=15)

        # Nav buttons
        self.nav_buttons = {}
        nav_items = [
            ("📊  Dashboard", self.show_dashboard),
            ("👥  Users", self.show_users),
            ("🔑  Roles", self.show_roles),
            ("📋  Access Requests", self.show_requests),
            ("🔍  Access Reviews", self.show_reviews),
            ("📜  Audit Log", self.show_audit),
            ("⚙️  Password Policy", self.show_policy),
            ("🔗  Integrations", self.show_integrations),
            ("📊  Reports", self.show_reports),
        ]
        for text, command in nav_items:
            btn = ctk.CTkButton(
                self.sidebar, text=text, command=command,
                fg_color="transparent", text_color=COLORS['text'],
                hover_color=COLORS['accent'], anchor="w",
                font=ctk.CTkFont(size=14), height=40
            )
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[text] = btn

        # Bottom info
        ctk.CTkFrame(self.sidebar, height=1, fg_color=COLORS['text_dim']).pack(fill="x", padx=20, pady=15, side="bottom")
        ctk.CTkLabel(self.sidebar, text="v1.0.0 — SecureAccess", font=ctk.CTkFont(size=10),
                     text_color=COLORS['text_dim']).pack(side="bottom", pady=(0, 10))

    def _set_active_nav(self, label):
        for text, btn in self.nav_buttons.items():
            if text == label:
                btn.configure(fg_color=COLORS['accent'])
            else:
                btn.configure(fg_color="transparent")

    # ══════════════════════════════════════════════
    #  MAIN AREA
    # ══════════════════════════════════════════════
    def _build_main_area(self):
        self.main_frame = ctk.CTkFrame(self, fg_color=COLORS['bg_dark'], corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

    def _clear_main(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def _make_header(self, title, subtitle=""):
        header = ctk.CTkFrame(self.main_frame, fg_color="transparent", height=60)
        header.pack(fill="x", padx=30, pady=(20, 10))
        ctk.CTkLabel(header, text=title, font=ctk.CTkFont(size=26, weight="bold")).pack(anchor="w")
        if subtitle:
            ctk.CTkLabel(header, text=subtitle, font=ctk.CTkFont(size=13), text_color=COLORS['text_dim']).pack(anchor="w")
        return header

    # ══════════════════════════════════════════════
    #  DASHBOARD
    # ══════════════════════════════════════════════
    def show_dashboard(self):
        self._clear_main()
        self._set_active_nav("📊  Dashboard")
        self._make_header("Dashboard", "Security posture overview")

        stats = self.db.get_dashboard_stats()

        # Top stat cards row
        cards_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        cards_frame.pack(fill="x", padx=30, pady=10)
        for i in range(4):
            cards_frame.grid_columnconfigure(i, weight=1)

        card_data = [
            ("Total Users", str(stats['total_users']), f"{stats['active_users']} active", COLORS['accent_blue']),
            ("MFA Coverage", f"{(stats['mfa_enabled']/max(stats['active_users'],1)*100):.0f}%",
             f"{stats['mfa_enabled']}/{stats['active_users']} enabled", COLORS['accent_green'] if stats['mfa_disabled'] == 0 else COLORS['accent_orange']),
            ("Pending Requests", str(stats['pending_requests']),
             "Awaiting review" if stats['pending_requests'] > 0 else "All clear", COLORS['accent_yellow'] if stats['pending_requests'] > 0 else COLORS['accent_green']),
            ("Security Alerts", str(stats['recent_audit_warnings']),
             "Last 7 days", COLORS['critical'] if stats['recent_audit_warnings'] > 0 else COLORS['accent_green']),
        ]

        for i, (title, value, sub, color) in enumerate(card_data):
            card = ctk.CTkFrame(cards_frame, fg_color=COLORS['bg_card'], corner_radius=12)
            card.grid(row=0, column=i, padx=8, pady=5, sticky="nsew")
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12), text_color=COLORS['text_dim']).pack(padx=15, pady=(12, 0), anchor="w")
            ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=36, weight="bold"), text_color=color).pack(padx=15, anchor="w")
            ctk.CTkLabel(card, text=sub, font=ctk.CTkFont(size=11), text_color=COLORS['text_dim']).pack(padx=15, pady=(0, 12), anchor="w")

        # Bottom section: two columns
        bottom = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        bottom.pack(fill="both", expand=True, padx=30, pady=10)
        bottom.grid_columnconfigure(0, weight=1)
        bottom.grid_columnconfigure(1, weight=1)

        # Role distribution
        role_card = ctk.CTkFrame(bottom, fg_color=COLORS['bg_card'], corner_radius=12)
        role_card.grid(row=0, column=0, padx=(0, 8), pady=5, sticky="nsew")
        bottom.grid_rowconfigure(0, weight=1)
        ctk.CTkLabel(role_card, text="Role Distribution", font=ctk.CTkFont(size=16, weight="bold")).pack(padx=15, pady=(12, 8), anchor="w")

        role_scroll = ctk.CTkScrollableFrame(role_card, fg_color="transparent")
        role_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        for r in stats['role_distribution']:
            row = ctk.CTkFrame(role_scroll, fg_color="transparent")
            row.pack(fill="x", pady=2)
            risk_color = RISK_COLORS.get(r['risk_level'], COLORS['text_dim'])
            ctk.CTkLabel(row, text="●", text_color=risk_color, font=ctk.CTkFont(size=14)).pack(side="left", padx=(5, 8))
            ctk.CTkLabel(row, text=r['name'], font=ctk.CTkFont(size=13)).pack(side="left")
            ctk.CTkLabel(row, text=f"{r['user_count']} users", font=ctk.CTkFont(size=12),
                         text_color=COLORS['text_dim']).pack(side="right", padx=10)

        # User status & department
        status_card = ctk.CTkFrame(bottom, fg_color=COLORS['bg_card'], corner_radius=12)
        status_card.grid(row=0, column=1, padx=(8, 0), pady=5, sticky="nsew")
        ctk.CTkLabel(status_card, text="User Status Overview", font=ctk.CTkFont(size=16, weight="bold")).pack(padx=15, pady=(12, 8), anchor="w")

        status_items = [
            ("Active", stats['active_users'], COLORS['accent_green']),
            ("Inactive", stats['inactive_users'], COLORS['text_dim']),
            ("Locked", stats['locked_users'], COLORS['critical']),
            ("Pending Review", stats['pending_review'], COLORS['accent_yellow']),
        ]
        for label, count, color in status_items:
            row = ctk.CTkFrame(status_card, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=3)
            ctk.CTkLabel(row, text="●", text_color=color, font=ctk.CTkFont(size=14)).pack(side="left", padx=(0, 8))
            ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=13)).pack(side="left")
            ctk.CTkLabel(row, text=str(count), font=ctk.CTkFont(size=13, weight="bold"),
                         text_color=color).pack(side="right", padx=10)

        ctk.CTkLabel(status_card, text="Departments", font=ctk.CTkFont(size=14, weight="bold")).pack(padx=15, pady=(15, 5), anchor="w")
        for dept in stats['departments']:
            row = ctk.CTkFrame(status_card, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=2)
            ctk.CTkLabel(row, text=dept['department'] or 'Unknown', font=ctk.CTkFont(size=12)).pack(side="left")
            ctk.CTkLabel(row, text=str(dept['count']), font=ctk.CTkFont(size=12),
                         text_color=COLORS['text_dim']).pack(side="right", padx=10)

    # ══════════════════════════════════════════════
    #  USERS
    # ══════════════════════════════════════════════
    def show_users(self):
        self._clear_main()
        self._set_active_nav("👥  Users")
        header = self._make_header("User Management", "Manage user accounts and access")

        # Toolbar
        toolbar = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        toolbar.pack(fill="x", padx=30, pady=(0, 10))

        self.user_search = ctk.CTkEntry(toolbar, placeholder_text="🔍 Search users...", width=300)
        self.user_search.pack(side="left")
        self.user_search.bind("<KeyRelease>", lambda e: self._refresh_users())

        self.user_status_filter = ctk.CTkComboBox(toolbar, values=["all", "active", "inactive", "locked", "pending_review"],
                                                   width=150, command=lambda v: self._refresh_users())
        self.user_status_filter.set("all")
        self.user_status_filter.pack(side="left", padx=10)

        ctk.CTkButton(toolbar, text="+ Add User", fg_color=COLORS['accent_green'],
                      hover_color="#00a884", command=self._add_user_dialog).pack(side="right")
        ctk.CTkButton(toolbar, text="Export CSV", fg_color=COLORS['accent_blue'],
                      hover_color="#0873c4", command=self._export_users_csv).pack(side="right", padx=10)

        # Table
        self.user_table_frame = ctk.CTkScrollableFrame(self.main_frame, fg_color=COLORS['bg_card'], corner_radius=12)
        self.user_table_frame.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        self._refresh_users()

    def _refresh_users(self):
        for w in self.user_table_frame.winfo_children():
            w.destroy()

        # Header row
        hdr = ctk.CTkFrame(self.user_table_frame, fg_color=COLORS['bg_sidebar'], corner_radius=6)
        hdr.pack(fill="x", padx=5, pady=(5, 2))
        cols = [("Username", 120), ("Name", 160), ("Email", 200), ("Department", 120), ("Status", 100), ("MFA", 60), ("Actions", 200)]
        for text, width in cols:
            ctk.CTkLabel(hdr, text=text, font=ctk.CTkFont(size=12, weight="bold"), width=width).pack(side="left", padx=5, pady=8)

        search = self.user_search.get() if hasattr(self, 'user_search') else None
        status = self.user_status_filter.get() if hasattr(self, 'user_status_filter') else None
        users = self.db.get_users(status_filter=status, search=search)

        for user in users:
            row = ctk.CTkFrame(self.user_table_frame, fg_color="transparent", corner_radius=6)
            row.pack(fill="x", padx=5, pady=1)

            ctk.CTkLabel(row, text=user['username'], width=120, font=ctk.CTkFont(size=12)).pack(side="left", padx=5, pady=6)
            ctk.CTkLabel(row, text=user['display_name'], width=160, font=ctk.CTkFont(size=12)).pack(side="left", padx=5)
            ctk.CTkLabel(row, text=user['email'] or '', width=200, font=ctk.CTkFont(size=11), text_color=COLORS['text_dim']).pack(side="left", padx=5)
            ctk.CTkLabel(row, text=user['department'] or '', width=120, font=ctk.CTkFont(size=12)).pack(side="left", padx=5)

            status_colors = {'active': COLORS['accent_green'], 'inactive': COLORS['text_dim'],
                           'locked': COLORS['critical'], 'pending_review': COLORS['accent_yellow']}
            ctk.CTkLabel(row, text=user['status'].upper(), width=100, font=ctk.CTkFont(size=11, weight="bold"),
                         text_color=status_colors.get(user['status'], COLORS['text'])).pack(side="left", padx=5)

            mfa_text = "✅" if user['mfa_enabled'] else "❌"
            ctk.CTkLabel(row, text=mfa_text, width=60, font=ctk.CTkFont(size=14)).pack(side="left", padx=5)

            btn_frame = ctk.CTkFrame(row, fg_color="transparent", width=200)
            btn_frame.pack(side="left", padx=5)
            uid = user['id']
            ctk.CTkButton(btn_frame, text="Edit", width=55, height=28, font=ctk.CTkFont(size=11),
                         command=lambda u=uid: self._edit_user_dialog(u)).pack(side="left", padx=2)
            ctk.CTkButton(btn_frame, text="Roles", width=55, height=28, font=ctk.CTkFont(size=11),
                         fg_color=COLORS['accent_blue'], command=lambda u=uid: self._manage_user_roles(u)).pack(side="left", padx=2)
            ctk.CTkButton(btn_frame, text="Delete", width=55, height=28, font=ctk.CTkFont(size=11),
                         fg_color=COLORS['critical'], hover_color="#c0392b",
                         command=lambda u=uid: self._delete_user(u)).pack(side="left", padx=2)

    def _add_user_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Add New User")
        dialog.geometry("450x650")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="Add New User", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(20, 15))

        fields = {}
        for label, key, placeholder in [
            ("Username*", "username", "e.g. jdoe"),
            ("Display Name*", "display_name", "e.g. Jane Doe"),
            ("Email", "email", "e.g. jdoe@company.com"),
            ("Department", "department", "e.g. Engineering"),
            ("Title", "title", "e.g. Software Engineer"),
        ]:
            ctk.CTkLabel(dialog, text=label, font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
            entry = ctk.CTkEntry(dialog, placeholder_text=placeholder, width=380)
            entry.pack(padx=30, pady=(0, 8))
            fields[key] = entry

        ctk.CTkLabel(dialog, text="Status", font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
        status_var = ctk.CTkComboBox(dialog, values=["active", "inactive", "pending_review"], width=380)
        status_var.set("active")
        status_var.pack(padx=30, pady=(0, 8))

        mfa_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(dialog, text="Enable MFA", variable=mfa_var).pack(padx=30, pady=5, anchor="w")

        notes_label = ctk.CTkLabel(dialog, text="Notes", font=ctk.CTkFont(size=12))
        notes_label.pack(padx=30, anchor="w")
        notes = ctk.CTkTextbox(dialog, height=60, width=380)
        notes.pack(padx=30, pady=(0, 10))

        def save():
            username = fields['username'].get().strip()
            display_name = fields['display_name'].get().strip()
            if not username or not display_name:
                messagebox.showerror("Error", "Username and Display Name are required.")
                return
            try:
                self.db.create_user(
                    username=username,
                    display_name=display_name,
                    email=fields['email'].get().strip(),
                    department=fields['department'].get().strip(),
                    title=fields['title'].get().strip(),
                    status=status_var.get(),
                    mfa_enabled=1 if mfa_var.get() else 0,
                    notes=notes.get("1.0", "end").strip(),
                    created_by='admin'
                )
                dialog.destroy()
                self._refresh_users()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ctk.CTkButton(dialog, text="Save User", fg_color=COLORS['accent_green'], command=save).pack(pady=15)

    def _edit_user_dialog(self, user_id):
        user = self.db.get_user(user_id)
        if not user:
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Edit User — {user['username']}")
        dialog.geometry("450x650")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text=f"Edit: {user['display_name']}", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(20, 15))

        fields = {}
        for label, key, val in [
            ("Display Name", "display_name", user['display_name']),
            ("Email", "email", user['email'] or ''),
            ("Department", "department", user['department'] or ''),
            ("Title", "title", user['title'] or ''),
        ]:
            ctk.CTkLabel(dialog, text=label, font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
            entry = ctk.CTkEntry(dialog, width=380)
            entry.insert(0, val)
            entry.pack(padx=30, pady=(0, 8))
            fields[key] = entry

        ctk.CTkLabel(dialog, text="Status", font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
        status_var = ctk.CTkComboBox(dialog, values=["active", "inactive", "locked", "pending_review"], width=380)
        status_var.set(user['status'])
        status_var.pack(padx=30, pady=(0, 8))

        mfa_var = ctk.BooleanVar(value=bool(user['mfa_enabled']))
        ctk.CTkCheckBox(dialog, text="Enable MFA", variable=mfa_var).pack(padx=30, pady=5, anchor="w")

        def save():
            try:
                self.db.update_user(user_id,
                    display_name=fields['display_name'].get().strip(),
                    email=fields['email'].get().strip(),
                    department=fields['department'].get().strip(),
                    title=fields['title'].get().strip(),
                    status=status_var.get(),
                    mfa_enabled=1 if mfa_var.get() else 0,
                )
                self.db.log_audit('admin', 'USER_UPDATED', 'user', user_id, user['username'],
                                  f"User {user['username']} updated")
                dialog.destroy()
                self._refresh_users()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ctk.CTkButton(dialog, text="Save Changes", fg_color=COLORS['accent_green'], command=save).pack(pady=15)

    def _delete_user(self, user_id):
        user = self.db.get_user(user_id)
        if user and messagebox.askyesno("Confirm Delete", f"Delete user '{user['display_name']}'?\nThis cannot be undone."):
            self.db.delete_user(user_id)
            self._refresh_users()

    def _manage_user_roles(self, user_id):
        user = self.db.get_user(user_id)
        if not user:
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Manage Roles — {user['display_name']}")
        dialog.geometry("500x500")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text=f"Roles for {user['display_name']}", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(15, 10))

        # Current roles
        ctk.CTkLabel(dialog, text="Current Roles:", font=ctk.CTkFont(size=14, weight="bold")).pack(padx=20, anchor="w")
        current_frame = ctk.CTkScrollableFrame(dialog, height=150)
        current_frame.pack(fill="x", padx=20, pady=5)

        user_roles = self.db.get_user_roles(user_id)
        for ur in user_roles:
            row = ctk.CTkFrame(current_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)
            risk_color = RISK_COLORS.get(ur['risk_level'], COLORS['text_dim'])
            ctk.CTkLabel(row, text="●", text_color=risk_color).pack(side="left", padx=5)
            ctk.CTkLabel(row, text=ur['name'], font=ctk.CTkFont(size=13)).pack(side="left", padx=5)
            ctk.CTkLabel(row, text=f"({ur['risk_level']})", font=ctk.CTkFont(size=11),
                         text_color=COLORS['text_dim']).pack(side="left")
            rid = ur['id']
            ctk.CTkButton(row, text="Revoke", width=70, height=26, font=ctk.CTkFont(size=11),
                         fg_color=COLORS['critical'], hover_color="#c0392b",
                         command=lambda r=rid: self._revoke_and_refresh(user_id, r, dialog)).pack(side="right", padx=5)

        # Assign new role
        ctk.CTkLabel(dialog, text="Assign New Role:", font=ctk.CTkFont(size=14, weight="bold")).pack(padx=20, pady=(15, 5), anchor="w")
        all_roles = self.db.get_roles()
        current_role_ids = {ur['id'] for ur in user_roles}
        available = [r for r in all_roles if r['id'] not in current_role_ids]

        if available:
            role_names = {r['name']: r['id'] for r in available}
            role_combo = ctk.CTkComboBox(dialog, values=list(role_names.keys()), width=300)
            role_combo.pack(padx=20, pady=5)

            just_entry = ctk.CTkEntry(dialog, placeholder_text="Justification...", width=300)
            just_entry.pack(padx=20, pady=5)

            def assign():
                selected = role_combo.get()
                if selected in role_names:
                    self.db.assign_role(user_id, role_names[selected], justification=just_entry.get())
                    dialog.destroy()
                    self._manage_user_roles(user_id)

            ctk.CTkButton(dialog, text="Assign Role", fg_color=COLORS['accent_green'], command=assign).pack(pady=10)
        else:
            ctk.CTkLabel(dialog, text="All roles already assigned", text_color=COLORS['text_dim']).pack(padx=20)

    def _revoke_and_refresh(self, user_id, role_id, dialog):
        self.db.revoke_role(user_id, role_id)
        dialog.destroy()
        self._manage_user_roles(user_id)

    def _export_users_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        users = self.db.get_users()
        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Username', 'Display Name', 'Email', 'Department', 'Title', 'Status', 'MFA Enabled', 'Created'])
            for u in users:
                writer.writerow([u['username'], u['display_name'], u['email'], u['department'],
                               u['title'], u['status'], 'Yes' if u['mfa_enabled'] else 'No', u['created_at']])
        messagebox.showinfo("Export Complete", f"Users exported to:\n{path}")

    # ══════════════════════════════════════════════
    #  ROLES
    # ══════════════════════════════════════════════
    def show_roles(self):
        self._clear_main()
        self._set_active_nav("🔑  Roles")
        self._make_header("Role Management", "Define roles and permission boundaries")

        toolbar = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        toolbar.pack(fill="x", padx=30, pady=(0, 10))
        ctk.CTkButton(toolbar, text="+ Create Role", fg_color=COLORS['accent_green'],
                      command=self._add_role_dialog).pack(side="right")

        scroll = ctk.CTkScrollableFrame(self.main_frame, fg_color=COLORS['bg_card'], corner_radius=12)
        scroll.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        roles = self.db.get_roles()
        for role in roles:
            card = ctk.CTkFrame(scroll, fg_color=COLORS['bg_dark'], corner_radius=10)
            card.pack(fill="x", padx=8, pady=4)

            left = ctk.CTkFrame(card, fg_color="transparent")
            left.pack(side="left", fill="x", expand=True, padx=15, pady=12)

            title_row = ctk.CTkFrame(left, fg_color="transparent")
            title_row.pack(anchor="w")
            risk_color = RISK_COLORS.get(role['risk_level'], COLORS['text_dim'])
            ctk.CTkLabel(title_row, text="●", text_color=risk_color, font=ctk.CTkFont(size=16)).pack(side="left", padx=(0, 8))
            ctk.CTkLabel(title_row, text=role['name'], font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")
            ctk.CTkLabel(title_row, text=f"  [{role['risk_level'].upper()}]", font=ctk.CTkFont(size=11),
                         text_color=risk_color).pack(side="left")

            ctk.CTkLabel(left, text=role['description'] or '', font=ctk.CTkFont(size=12),
                         text_color=COLORS['text_dim']).pack(anchor="w")

            details = f"Max Session: {role['max_session_hours']}h  |  MFA Required: {'Yes' if role['requires_mfa'] else 'No'}"
            ctk.CTkLabel(left, text=details, font=ctk.CTkFont(size=11), text_color=COLORS['text_dim']).pack(anchor="w", pady=(3, 0))

            # User count
            users_in_role = self.db.get_role_users(role['id'])
            ctk.CTkLabel(left, text=f"👥 {len(users_in_role)} users assigned", font=ctk.CTkFont(size=11),
                         text_color=COLORS['accent_blue']).pack(anchor="w", pady=(2, 0))

            right = ctk.CTkFrame(card, fg_color="transparent")
            right.pack(side="right", padx=15, pady=12)
            rid = role['id']
            ctk.CTkButton(right, text="Edit", width=70, height=30,
                         command=lambda r=rid: self._edit_role_dialog(r)).pack(pady=2)
            ctk.CTkButton(right, text="Members", width=70, height=30, fg_color=COLORS['accent_blue'],
                         command=lambda r=rid: self._show_role_members(r)).pack(pady=2)

    def _add_role_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Create New Role")
        dialog.geometry("450x600")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="Create New Role", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(20, 15))

        fields = {}
        for label, key, ph in [("Role Name*", "name", "e.g. Database Admin"), ("Description", "description", "Role description...")]:
            ctk.CTkLabel(dialog, text=label, font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
            e = ctk.CTkEntry(dialog, placeholder_text=ph, width=380)
            e.pack(padx=30, pady=(0, 8))
            fields[key] = e

        ctk.CTkLabel(dialog, text="Risk Level", font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
        risk = ctk.CTkComboBox(dialog, values=["low", "medium", "high", "critical"], width=380)
        risk.set("low")
        risk.pack(padx=30, pady=(0, 8))

        ctk.CTkLabel(dialog, text="Max Session Hours", font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
        hours = ctk.CTkEntry(dialog, width=380)
        hours.insert(0, "8")
        hours.pack(padx=30, pady=(0, 8))

        mfa_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(dialog, text="Require MFA", variable=mfa_var).pack(padx=30, pady=5, anchor="w")

        def save():
            name = fields['name'].get().strip()
            if not name:
                messagebox.showerror("Error", "Role name is required.")
                return
            try:
                self.db.create_role(
                    name=name, description=fields['description'].get().strip(),
                    risk_level=risk.get(), max_session_hours=int(hours.get() or 8),
                    requires_mfa=1 if mfa_var.get() else 0
                )
                self.db.log_audit('admin', 'ROLE_CREATED', 'role', None, name, f"Role '{name}' created")
                dialog.destroy()
                self.show_roles()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ctk.CTkButton(dialog, text="Create Role", fg_color=COLORS['accent_green'], command=save).pack(pady=15)

    def _edit_role_dialog(self, role_id):
        role = self.db.get_role(role_id)
        if not role:
            return
        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Edit Role — {role['name']}")
        dialog.geometry("450x600")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text=f"Edit: {role['name']}", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(20, 15))

        fields = {}
        for label, key, val in [("Description", "description", role['description'] or '')]:
            ctk.CTkLabel(dialog, text=label, font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
            e = ctk.CTkEntry(dialog, width=380)
            e.insert(0, val)
            e.pack(padx=30, pady=(0, 8))
            fields[key] = e

        ctk.CTkLabel(dialog, text="Risk Level", font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
        risk = ctk.CTkComboBox(dialog, values=["low", "medium", "high", "critical"], width=380)
        risk.set(role['risk_level'])
        risk.pack(padx=30, pady=(0, 8))

        ctk.CTkLabel(dialog, text="Max Session Hours", font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
        hours = ctk.CTkEntry(dialog, width=380)
        hours.insert(0, str(role['max_session_hours']))
        hours.pack(padx=30, pady=(0, 8))

        mfa_var = ctk.BooleanVar(value=bool(role['requires_mfa']))
        ctk.CTkCheckBox(dialog, text="Require MFA", variable=mfa_var).pack(padx=30, pady=5, anchor="w")

        def save():
            try:
                self.db.update_role(role_id,
                    description=fields['description'].get().strip(),
                    risk_level=risk.get(), max_session_hours=int(hours.get() or 8),
                    requires_mfa=1 if mfa_var.get() else 0
                )
                dialog.destroy()
                self.show_roles()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ctk.CTkButton(dialog, text="Save Changes", fg_color=COLORS['accent_green'], command=save).pack(pady=15)

    def _show_role_members(self, role_id):
        role = self.db.get_role(role_id)
        members = self.db.get_role_users(role_id)
        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Members — {role['name']}")
        dialog.geometry("400x400")
        dialog.transient(self)

        ctk.CTkLabel(dialog, text=f"{role['name']} Members ({len(members)})",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)

        scroll = ctk.CTkScrollableFrame(dialog)
        scroll.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        for m in members:
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=f"{m['display_name']} ({m['username']})", font=ctk.CTkFont(size=13)).pack(side="left", padx=5)
            ctk.CTkLabel(row, text=f"Granted: {m['granted_at'][:10] if m['granted_at'] else 'N/A'}",
                         font=ctk.CTkFont(size=11), text_color=COLORS['text_dim']).pack(side="right", padx=5)

    # ══════════════════════════════════════════════
    #  ACCESS REQUESTS
    # ══════════════════════════════════════════════
    def show_requests(self):
        self._clear_main()
        self._set_active_nav("📋  Access Requests")
        self._make_header("Access Requests", "Review and approve access change requests")

        toolbar = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        toolbar.pack(fill="x", padx=30, pady=(0, 10))

        self.req_filter = ctk.CTkComboBox(toolbar, values=["all", "pending", "approved", "denied"],
                                           command=lambda v: self._refresh_requests())
        self.req_filter.set("pending")
        self.req_filter.pack(side="left")
        ctk.CTkButton(toolbar, text="+ New Request", fg_color=COLORS['accent_green'],
                      command=self._new_request_dialog).pack(side="right")

        self.req_scroll = ctk.CTkScrollableFrame(self.main_frame, fg_color=COLORS['bg_card'], corner_radius=12)
        self.req_scroll.pack(fill="both", expand=True, padx=30, pady=(0, 20))
        self._refresh_requests()

    def _refresh_requests(self):
        for w in self.req_scroll.winfo_children():
            w.destroy()

        requests = self.db.get_access_requests(self.req_filter.get())
        if not requests:
            ctk.CTkLabel(self.req_scroll, text="No requests found", text_color=COLORS['text_dim'],
                         font=ctk.CTkFont(size=14)).pack(pady=30)
            return

        for req in requests:
            card = ctk.CTkFrame(self.req_scroll, fg_color=COLORS['bg_dark'], corner_radius=10)
            card.pack(fill="x", padx=8, pady=4)

            left = ctk.CTkFrame(card, fg_color="transparent")
            left.pack(side="left", fill="x", expand=True, padx=15, pady=10)

            status_colors = {'pending': COLORS['accent_yellow'], 'approved': COLORS['accent_green'],
                           'denied': COLORS['critical'], 'expired': COLORS['text_dim']}
            ctk.CTkLabel(left, text=f"[{req['status'].upper()}] {req['request_type'].upper()}: {req['role_name']}",
                         font=ctk.CTkFont(size=14, weight="bold"),
                         text_color=status_colors.get(req['status'])).pack(anchor="w")
            ctk.CTkLabel(left, text=f"User: {req['user_name']} ({req['username']})  |  Requested: {req['requested_at'][:16]}",
                         font=ctk.CTkFont(size=12), text_color=COLORS['text_dim']).pack(anchor="w")
            if req['justification']:
                ctk.CTkLabel(left, text=f"Justification: {req['justification']}", font=ctk.CTkFont(size=11),
                             text_color=COLORS['text_dim']).pack(anchor="w")

            if req['status'] == 'pending':
                right = ctk.CTkFrame(card, fg_color="transparent")
                right.pack(side="right", padx=15, pady=10)
                rid = req['id']
                uid = req['user_id']
                roleid = req['role_id']
                ctk.CTkButton(right, text="✓ Approve", width=90, height=30, fg_color=COLORS['accent_green'],
                             command=lambda r=rid, u=uid, ro=roleid: self._approve_request(r, u, ro)).pack(pady=2)
                ctk.CTkButton(right, text="✗ Deny", width=90, height=30, fg_color=COLORS['critical'],
                             command=lambda r=rid: self._deny_request(r)).pack(pady=2)

    def _approve_request(self, request_id, user_id, role_id):
        self.db.review_access_request(request_id, 'approved', 'admin')
        self.db.assign_role(user_id, role_id, 'admin', 'Approved via access request')
        self._refresh_requests()

    def _deny_request(self, request_id):
        self.db.review_access_request(request_id, 'denied', 'admin', 'Request denied')
        self._refresh_requests()

    def _new_request_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("New Access Request")
        dialog.geometry("450x480")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="New Access Request", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(20, 15))

        users = self.db.get_users(status_filter='active')
        user_map = {f"{u['display_name']} ({u['username']})": u['id'] for u in users}
        ctk.CTkLabel(dialog, text="User", font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
        user_combo = ctk.CTkComboBox(dialog, values=list(user_map.keys()), width=380)
        user_combo.pack(padx=30, pady=(0, 8))

        roles = self.db.get_roles()
        role_map = {r['name']: r['id'] for r in roles}
        ctk.CTkLabel(dialog, text="Role", font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
        role_combo = ctk.CTkComboBox(dialog, values=list(role_map.keys()), width=380)
        role_combo.pack(padx=30, pady=(0, 8))

        ctk.CTkLabel(dialog, text="Type", font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
        type_combo = ctk.CTkComboBox(dialog, values=["grant", "revoke"], width=380)
        type_combo.set("grant")
        type_combo.pack(padx=30, pady=(0, 8))

        ctk.CTkLabel(dialog, text="Justification", font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
        just = ctk.CTkEntry(dialog, placeholder_text="Business justification...", width=380)
        just.pack(padx=30, pady=(0, 8))

        def submit():
            u = user_combo.get()
            r = role_combo.get()
            if u in user_map and r in role_map:
                self.db.create_access_request(user_map[u], role_map[r], type_combo.get(), just.get())
                self.db.log_audit('admin', 'ACCESS_REQUEST_CREATED', 'request', None, f"{u} -> {r}",
                                  f"Request type: {type_combo.get()}")
                dialog.destroy()
                self._refresh_requests()

        ctk.CTkButton(dialog, text="Submit Request", fg_color=COLORS['accent_green'], command=submit).pack(pady=15)

    # ══════════════════════════════════════════════
    #  ACCESS REVIEWS
    # ══════════════════════════════════════════════
    def show_reviews(self):
        self._clear_main()
        self._set_active_nav("🔍  Access Reviews")
        self._make_header("Access Reviews", "Periodic certification of user access rights")

        toolbar = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        toolbar.pack(fill="x", padx=30, pady=(0, 10))
        ctk.CTkButton(toolbar, text="+ Start New Review", fg_color=COLORS['accent_green'],
                      command=self._start_review_dialog).pack(side="right")

        scroll = ctk.CTkScrollableFrame(self.main_frame, fg_color=COLORS['bg_card'], corner_radius=12)
        scroll.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        reviews = self.db.get_access_reviews()
        if not reviews:
            ctk.CTkLabel(scroll, text="No access reviews yet. Start one to certify user access.",
                         text_color=COLORS['text_dim'], font=ctk.CTkFont(size=14)).pack(pady=30)
            return

        for rev in reviews:
            card = ctk.CTkFrame(scroll, fg_color=COLORS['bg_dark'], corner_radius=10)
            card.pack(fill="x", padx=8, pady=4)
            left = ctk.CTkFrame(card, fg_color="transparent")
            left.pack(side="left", fill="x", expand=True, padx=15, pady=10)

            status_colors = {'open': COLORS['accent_blue'], 'in_progress': COLORS['accent_yellow'],
                           'completed': COLORS['accent_green'], 'cancelled': COLORS['text_dim']}
            ctk.CTkLabel(left, text=rev['name'], font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w")
            ctk.CTkLabel(left, text=f"Status: {rev['status'].upper()}  |  Created: {rev['created_at'][:10]}",
                         font=ctk.CTkFont(size=12), text_color=status_colors.get(rev['status'])).pack(anchor="w")
            if rev['due_date']:
                ctk.CTkLabel(left, text=f"Due: {rev['due_date']}", font=ctk.CTkFont(size=11),
                             text_color=COLORS['text_dim']).pack(anchor="w")

            right = ctk.CTkFrame(card, fg_color="transparent")
            right.pack(side="right", padx=15, pady=10)
            rid = rev['id']
            ctk.CTkButton(right, text="Review", width=80, height=30,
                         command=lambda r=rid: self._conduct_review(r)).pack()

    def _start_review_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Start Access Review")
        dialog.geometry("400x300")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="New Access Review", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(20, 15))

        ctk.CTkLabel(dialog, text="Review Name", font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
        name = ctk.CTkEntry(dialog, placeholder_text="e.g. Q1 2026 Quarterly Review", width=340)
        name.pack(padx=30, pady=(0, 8))

        ctk.CTkLabel(dialog, text="Due Date (YYYY-MM-DD)", font=ctk.CTkFont(size=12)).pack(padx=30, anchor="w")
        due = ctk.CTkEntry(dialog, placeholder_text="2026-03-31", width=340)
        due.pack(padx=30, pady=(0, 8))

        def create():
            n = name.get().strip()
            if not n:
                messagebox.showerror("Error", "Review name is required.")
                return
            self.db.create_access_review(n, due.get().strip() or None)
            dialog.destroy()
            self.show_reviews()

        ctk.CTkButton(dialog, text="Start Review", fg_color=COLORS['accent_green'], command=create).pack(pady=15)

    def _conduct_review(self, review_id):
        items = self.db.get_review_items(review_id)
        dialog = ctk.CTkToplevel(self)
        dialog.title("Conduct Access Review")
        dialog.geometry("700x500")
        dialog.transient(self)

        ctk.CTkLabel(dialog, text="Access Review Items", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)

        scroll = ctk.CTkScrollableFrame(dialog)
        scroll.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        for item in items:
            row = ctk.CTkFrame(scroll, fg_color=COLORS['bg_dark'], corner_radius=8)
            row.pack(fill="x", pady=3, padx=5)

            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=10, pady=8)

            risk_color = RISK_COLORS.get(item['risk_level'], COLORS['text_dim'])
            ctk.CTkLabel(info, text=f"{item['user_name']} ({item['username']})",
                         font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w")
            ctk.CTkLabel(info, text=f"Role: {item['role_name']} [{item['risk_level'].upper()}]  |  Dept: {item['department']}",
                         font=ctk.CTkFont(size=11), text_color=risk_color).pack(anchor="w")

            if item['decision']:
                ctk.CTkLabel(info, text=f"Decision: {item['decision'].upper()}", font=ctk.CTkFont(size=11),
                             text_color=COLORS['accent_green'] if item['decision'] == 'certify' else COLORS['critical']).pack(anchor="w")
            else:
                btns = ctk.CTkFrame(row, fg_color="transparent")
                btns.pack(side="right", padx=10, pady=8)
                iid = item['id']
                ctk.CTkButton(btns, text="✓ Certify", width=80, height=28, fg_color=COLORS['accent_green'],
                             command=lambda i=iid: self._decide_review_item(i, 'certify', review_id, dialog)).pack(pady=1)
                ctk.CTkButton(btns, text="✗ Revoke", width=80, height=28, fg_color=COLORS['critical'],
                             command=lambda i=iid: self._decide_review_item(i, 'revoke', review_id, dialog)).pack(pady=1)

    def _decide_review_item(self, item_id, decision, review_id, dialog):
        self.db.conn.execute("UPDATE review_items SET decision=?, decided_at=datetime('now') WHERE id=?", (decision, item_id))
        self.db.conn.commit()
        dialog.destroy()
        self._conduct_review(review_id)

    # ══════════════════════════════════════════════
    #  AUDIT LOG
    # ══════════════════════════════════════════════
    def show_audit(self):
        self._clear_main()
        self._set_active_nav("📜  Audit Log")
        self._make_header("Audit Log", "Complete record of all security-relevant actions")

        toolbar = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        toolbar.pack(fill="x", padx=30, pady=(0, 10))

        self.audit_search = ctk.CTkEntry(toolbar, placeholder_text="🔍 Search audit log...", width=300)
        self.audit_search.pack(side="left")
        self.audit_search.bind("<KeyRelease>", lambda e: self._refresh_audit())

        self.audit_severity = ctk.CTkComboBox(toolbar, values=["all", "info", "warning", "critical"],
                                               command=lambda v: self._refresh_audit(), width=120)
        self.audit_severity.set("all")
        self.audit_severity.pack(side="left", padx=10)

        ctk.CTkButton(toolbar, text="Export Log", fg_color=COLORS['accent_blue'],
                      command=self._export_audit_csv).pack(side="right")

        self.audit_scroll = ctk.CTkScrollableFrame(self.main_frame, fg_color=COLORS['bg_card'], corner_radius=12)
        self.audit_scroll.pack(fill="both", expand=True, padx=30, pady=(0, 20))
        self._refresh_audit()

    def _refresh_audit(self):
        for w in self.audit_scroll.winfo_children():
            w.destroy()

        search = self.audit_search.get() if hasattr(self, 'audit_search') else None
        severity = self.audit_severity.get() if hasattr(self, 'audit_severity') else None
        entries = self.db.get_audit_log(limit=200, severity_filter=severity, search=search)

        severity_icons = {'info': 'ℹ️', 'warning': '⚠️', 'critical': '🚨'}
        severity_colors = {'info': COLORS['accent_blue'], 'warning': COLORS['accent_yellow'], 'critical': COLORS['critical']}

        for entry in entries:
            row = ctk.CTkFrame(self.audit_scroll, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=1)

            icon = severity_icons.get(entry['severity'], 'ℹ️')
            color = severity_colors.get(entry['severity'], COLORS['text_dim'])

            ctk.CTkLabel(row, text=icon, width=30).pack(side="left", padx=(5, 0))
            ctk.CTkLabel(row, text=entry['timestamp'][:19] if entry['timestamp'] else '', width=160,
                         font=ctk.CTkFont(size=11), text_color=COLORS['text_dim']).pack(side="left", padx=5)
            ctk.CTkLabel(row, text=entry['actor'], width=80, font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=5)
            ctk.CTkLabel(row, text=entry['action'], width=180, font=ctk.CTkFont(size=12), text_color=color).pack(side="left", padx=5)
            ctk.CTkLabel(row, text=entry['target_name'] or '', width=120, font=ctk.CTkFont(size=11)).pack(side="left", padx=5)
            ctk.CTkLabel(row, text=entry['details'] or '', font=ctk.CTkFont(size=11),
                         text_color=COLORS['text_dim']).pack(side="left", padx=5, fill="x", expand=True)

    def _export_audit_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        entries = self.db.get_audit_log(limit=10000)
        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Severity', 'Actor', 'Action', 'Target Type', 'Target', 'Details'])
            for e in entries:
                writer.writerow([e['timestamp'], e['severity'], e['actor'], e['action'],
                               e['target_type'], e['target_name'], e['details']])
        messagebox.showinfo("Export Complete", f"Audit log exported to:\n{path}")

    # ══════════════════════════════════════════════
    #  PASSWORD POLICY
    # ══════════════════════════════════════════════
    def show_policy(self):
        self._clear_main()
        self._set_active_nav("⚙️  Password Policy")
        self._make_header("Password Policy", "Configure organization-wide password requirements")

        policy = self.db.get_password_policy()
        card = ctk.CTkFrame(self.main_frame, fg_color=COLORS['bg_card'], corner_radius=12)
        card.pack(fill="x", padx=30, pady=10)

        fields = {}
        field_defs = [
            ("Minimum Password Length", "min_length", str(policy['min_length']), "Minimum number of characters"),
            ("Password Max Age (days)", "max_age_days", str(policy['max_age_days']), "Days before password expires"),
            ("Password History Count", "history_count", str(policy['history_count']), "Number of previous passwords to remember"),
            ("Lockout Threshold", "lockout_threshold", str(policy['lockout_threshold']), "Failed attempts before lockout"),
            ("Lockout Duration (minutes)", "lockout_duration_minutes", str(policy['lockout_duration_minutes']), "Minutes account stays locked"),
        ]

        for label, key, val, desc in field_defs:
            frame = ctk.CTkFrame(card, fg_color="transparent")
            frame.pack(fill="x", padx=20, pady=5)
            left = ctk.CTkFrame(frame, fg_color="transparent")
            left.pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(left, text=label, font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
            ctk.CTkLabel(left, text=desc, font=ctk.CTkFont(size=11), text_color=COLORS['text_dim']).pack(anchor="w")
            entry = ctk.CTkEntry(frame, width=100)
            entry.insert(0, val)
            entry.pack(side="right", padx=10)
            fields[key] = entry

        # Checkboxes
        checks = {}
        check_defs = [
            ("Require Uppercase Letters", "require_uppercase", policy['require_uppercase']),
            ("Require Lowercase Letters", "require_lowercase", policy['require_lowercase']),
            ("Require Digits", "require_digits", policy['require_digits']),
            ("Require Special Characters", "require_special", policy['require_special']),
        ]
        check_frame = ctk.CTkFrame(card, fg_color="transparent")
        check_frame.pack(fill="x", padx=20, pady=10)
        for label, key, val in check_defs:
            var = ctk.BooleanVar(value=bool(val))
            ctk.CTkCheckBox(check_frame, text=label, variable=var).pack(anchor="w", pady=3)
            checks[key] = var

        def save_policy():
            try:
                self.db.update_password_policy(
                    min_length=int(fields['min_length'].get()),
                    max_age_days=int(fields['max_age_days'].get()),
                    history_count=int(fields['history_count'].get()),
                    lockout_threshold=int(fields['lockout_threshold'].get()),
                    lockout_duration_minutes=int(fields['lockout_duration_minutes'].get()),
                    require_uppercase=1 if checks['require_uppercase'].get() else 0,
                    require_lowercase=1 if checks['require_lowercase'].get() else 0,
                    require_digits=1 if checks['require_digits'].get() else 0,
                    require_special=1 if checks['require_special'].get() else 0,
                )
                messagebox.showinfo("Success", "Password policy updated successfully.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

        ctk.CTkButton(card, text="Save Policy", fg_color=COLORS['accent_green'], command=save_policy).pack(pady=15)


    # ══════════════════════════════════════════════
    #  INTEGRATIONS
    # ══════════════════════════════════════════════
    def show_integrations(self):
        self._clear_main()
        self._set_active_nav("\U0001f517  Integrations")
        self._make_header("System Integrations", "Connect to external identity providers and infrastructure")

        scroll = ctk.CTkScrollableFrame(self.main_frame, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        for conn in self.connector_mgr.get_all_connectors():
            card = ctk.CTkFrame(scroll, fg_color=COLORS['bg_card'], corner_radius=12)
            card.pack(fill="x", padx=5, pady=6)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=15, pady=(12, 5))

            ctk.CTkLabel(top, text=f"{conn.icon}  {conn.display_name}",
                         font=ctk.CTkFont(size=17, weight="bold")).pack(side="left")

            status_color = COLORS['accent_green'] if conn.connected else COLORS['text_dim']
            status_text = "\u25cf CONNECTED" if conn.connected else "\u25cf DISCONNECTED"
            ctk.CTkLabel(top, text=status_text, font=ctk.CTkFont(size=12, weight="bold"),
                         text_color=status_color).pack(side="right")

            ctk.CTkLabel(card, text=conn.description, font=ctk.CTkFont(size=12),
                         text_color=COLORS['text_dim']).pack(padx=15, anchor="w")

            # Config summary
            config_items = []
            for k, v in conn.config.items():
                if "password" in k.lower() or "secret" in k.lower() or "token" in k.lower() or "key" in k.lower():
                    config_items.append(f"{k}: \u2022\u2022\u2022\u2022\u2022\u2022")
                elif isinstance(v, bool):
                    config_items.append(f"{k}: {'Yes' if v else 'No'}")
                else:
                    config_items.append(f"{k}: {v}")
            config_text = "  |  ".join(config_items[:4])
            if len(config_items) > 4:
                config_text += f"  | +{len(config_items)-4} more"
            ctk.CTkLabel(card, text=config_text, font=ctk.CTkFont(size=11),
                         text_color=COLORS['text_dim'], wraplength=900).pack(padx=15, anchor="w", pady=(2, 0))

            # Buttons
            btn_frame = ctk.CTkFrame(card, fg_color="transparent")
            btn_frame.pack(fill="x", padx=15, pady=(8, 12))

            cname = conn.name
            if conn.connected:
                ctk.CTkButton(btn_frame, text="Disconnect", width=100, height=30,
                             fg_color=COLORS['accent_orange'],
                             command=lambda c=cname: self._disconnect_connector(c)).pack(side="left", padx=3)
                ctk.CTkButton(btn_frame, text="Test", width=80, height=30,
                             fg_color=COLORS['accent_blue'],
                             command=lambda c=cname: self._test_connector(c)).pack(side="left", padx=3)
                ctk.CTkButton(btn_frame, text="Provision Log", width=110, height=30,
                             fg_color=COLORS['bg_sidebar'],
                             command=lambda c=cname: self._show_provision_log(c)).pack(side="left", padx=3)
            else:
                ctk.CTkButton(btn_frame, text="Connect", width=100, height=30,
                             fg_color=COLORS['accent_green'], hover_color="#00a884",
                             command=lambda c=cname: self._connect_connector(c)).pack(side="left", padx=3)
                ctk.CTkButton(btn_frame, text="Configure", width=100, height=30,
                             command=lambda c=cname: self._configure_connector(c)).pack(side="left", padx=3)

            # Show recent provisioning activity if connected
            if conn.connected and conn.provision_log:
                recent = conn.provision_log[-3:]
                ctk.CTkLabel(card, text="Recent Activity:", font=ctk.CTkFont(size=11, weight="bold"),
                             text_color=COLORS['accent_blue']).pack(padx=15, anchor="w")
                for log in reversed(recent):
                    color = COLORS['accent_green'] if log.success else COLORS['critical']
                    ctk.CTkLabel(card, text=f"  {'\u2713' if log.success else '\u2717'} [{log.action}] {log.target_user}: {log.details[:80]}",
                                 font=ctk.CTkFont(size=10), text_color=color, wraplength=900).pack(padx=15, anchor="w")
                ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

    def _connect_connector(self, name):
        conn = self.connector_mgr.get_connector(name)
        if conn:
            conn.connect()
            if conn.connected:
                self.db.log_audit('admin', 'CONNECTOR_CONNECTED', 'connector', None,
                                  conn.display_name, f"Connected to {conn.display_name}")
            self.show_integrations()

    def _disconnect_connector(self, name):
        conn = self.connector_mgr.get_connector(name)
        if conn:
            conn.disconnect()
            self.db.log_audit('admin', 'CONNECTOR_DISCONNECTED', 'connector', None,
                              conn.display_name, f"Disconnected from {conn.display_name}")
            self.show_integrations()

    def _test_connector(self, name):
        conn = self.connector_mgr.get_connector(name)
        if conn:
            result = conn.test_connection()
            status = "SUCCESS" if result.success else "FAILED"
            messagebox.showinfo(f"Connection Test",
                               f"Connector: {conn.display_name}\nStatus: {status}\n\nDetails:\n{result.details}"
                               + (f"\n\nError: {result.error}" if result.error else ""))

    def _configure_connector(self, name):
        conn = self.connector_mgr.get_connector(name)
        if not conn:
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Configure \u2014 {conn.display_name}")
        dialog.geometry("500x600")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text=f"{conn.icon}  Configure {conn.display_name}",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(20, 5))
        ctk.CTkLabel(dialog, text=conn.description, font=ctk.CTkFont(size=11),
                     text_color=COLORS['text_dim'], wraplength=440).pack(padx=30, pady=(0, 15))

        scroll = ctk.CTkScrollableFrame(dialog, height=350)
        scroll.pack(fill="x", padx=20, pady=(0, 10))

        entries = {}
        for field_def in conn.config_fields:
            key = field_def["key"]
            label = field_def.get("label", key)
            ftype = field_def.get("type", "text")

            if ftype == "checkbox":
                var = ctk.BooleanVar(value=bool(conn.config.get(key, False)))
                ctk.CTkCheckBox(scroll, text=label, variable=var).pack(anchor="w", padx=10, pady=4)
                entries[key] = ("checkbox", var)
            else:
                ctk.CTkLabel(scroll, text=label, font=ctk.CTkFont(size=12)).pack(padx=10, anchor="w", pady=(6, 0))
                entry = ctk.CTkEntry(scroll, width=420,
                                     placeholder_text=field_def.get("placeholder", ""),
                                     show="*" if ftype == "password" else "")
                current = conn.config.get(key, "")
                if current and ftype != "password":
                    entry.insert(0, str(current))
                entry.pack(padx=10, pady=(0, 2))
                entries[key] = ("text", entry)

        def save_config():
            for key, (ftype, widget) in entries.items():
                if ftype == "checkbox":
                    conn.config[key] = widget.get()
                else:
                    val = widget.get().strip()
                    if val:
                        conn.config[key] = val
            self.db.log_audit('admin', 'CONNECTOR_CONFIGURED', 'connector', None,
                              conn.display_name, f"Configuration updated for {conn.display_name}", 'warning')
            dialog.destroy()
            self.show_integrations()

        ctk.CTkButton(dialog, text="Save Configuration", fg_color=COLORS['accent_green'],
                      command=save_config).pack(pady=15)

    def _show_provision_log(self, name):
        conn = self.connector_mgr.get_connector(name)
        if not conn:
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Provisioning Log \u2014 {conn.display_name}")
        dialog.geometry("800x500")
        dialog.transient(self)

        ctk.CTkLabel(dialog, text=f"{conn.icon}  Provisioning Log \u2014 {conn.display_name}",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)

        scroll = ctk.CTkScrollableFrame(dialog)
        scroll.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        if not conn.provision_log:
            ctk.CTkLabel(scroll, text="No provisioning activity yet.",
                         text_color=COLORS['text_dim']).pack(pady=20)
        else:
            for log in reversed(conn.provision_log):
                row = ctk.CTkFrame(scroll, fg_color=COLORS['bg_dark'], corner_radius=8)
                row.pack(fill="x", padx=5, pady=3)
                color = COLORS['accent_green'] if log.success else COLORS['critical']
                icon = "\u2713" if log.success else "\u2717"
                ctk.CTkLabel(row, text=f"{icon} [{log.action}] {log.target_user}",
                             font=ctk.CTkFont(size=13, weight="bold"), text_color=color).pack(padx=10, pady=(6, 0), anchor="w")
                ctk.CTkLabel(row, text=log.details, font=ctk.CTkFont(size=11),
                             text_color=COLORS['text_dim'], wraplength=720).pack(padx=10, anchor="w")
                ctk.CTkLabel(row, text=log.timestamp[:19], font=ctk.CTkFont(size=10),
                             text_color=COLORS['text_dim']).pack(padx=10, pady=(0, 6), anchor="w")

    # ══════════════════════════════════════════════
    #  REPORTS
    # ══════════════════════════════════════════════
    def show_reports(self):
        self._clear_main()
        self._set_active_nav("📊  Reports")
        self._make_header("Reports & Compliance", "Generate security and compliance reports")

        reports = [
            ("User Access Report", "Complete listing of all users and their role assignments",
             "📋", self._report_user_access),
            ("MFA Compliance Report", "Users without MFA enabled, sorted by risk exposure",
             "🔐", self._report_mfa_compliance),
            ("Privileged Access Report", "Users with high/critical risk role assignments",
             "⚡", self._report_privileged_access),
            ("Inactive Users Report", "Users who are inactive or pending review",
             "👻", self._report_inactive_users),
            ("Role Summary Report", "All roles with member counts and risk levels",
             "🔑", self._report_role_summary),
            ("Audit Summary", "Recent audit events grouped by severity",
             "📜", self._report_audit_summary),
        ]

        grid = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        grid.pack(fill="both", expand=True, padx=30, pady=10)
        for i in range(3):
            grid.grid_columnconfigure(i, weight=1)

        for idx, (title, desc, icon, cmd) in enumerate(reports):
            row, col = divmod(idx, 3)
            card = ctk.CTkFrame(grid, fg_color=COLORS['bg_card'], corner_radius=12)
            card.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")
            grid.grid_rowconfigure(row, weight=1)

            ctk.CTkLabel(card, text=icon, font=ctk.CTkFont(size=36)).pack(pady=(20, 5))
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=15, weight="bold")).pack(padx=10)
            ctk.CTkLabel(card, text=desc, font=ctk.CTkFont(size=11), text_color=COLORS['text_dim'],
                         wraplength=200).pack(padx=10, pady=5)
            ctk.CTkButton(card, text="Generate", fg_color=COLORS['accent_blue'],
                         command=cmd).pack(pady=(5, 20))

    def _generate_report_window(self, title, headers, rows):
        dialog = ctk.CTkToplevel(self)
        dialog.title(title)
        dialog.geometry("800x500")
        dialog.transient(self)

        ctk.CTkLabel(dialog, text=title, font=ctk.CTkFont(size=20, weight="bold")).pack(pady=15)

        scroll = ctk.CTkScrollableFrame(dialog)
        scroll.pack(fill="both", expand=True, padx=15, pady=(0, 10))

        # Header
        hdr = ctk.CTkFrame(scroll, fg_color=COLORS['bg_sidebar'], corner_radius=6)
        hdr.pack(fill="x", pady=(0, 5))
        for h in headers:
            ctk.CTkLabel(hdr, text=h, font=ctk.CTkFont(size=12, weight="bold"), width=150).pack(side="left", padx=5, pady=6)

        for row_data in rows:
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x", pady=1)
            for val in row_data:
                ctk.CTkLabel(row, text=str(val), font=ctk.CTkFont(size=11), width=150).pack(side="left", padx=5, pady=4)

        def export():
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
            if path:
                with open(path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(headers)
                    writer.writerows(rows)
                messagebox.showinfo("Exported", f"Report saved to:\n{path}")

        ctk.CTkButton(dialog, text="Export CSV", fg_color=COLORS['accent_blue'], command=export).pack(pady=10)

    def _report_user_access(self):
        users = self.db.get_users()
        rows = []
        for u in users:
            roles = self.db.get_user_roles(u['id'])
            role_names = ', '.join(r['name'] for r in roles) or 'None'
            rows.append([u['username'], u['display_name'], u['department'], u['status'], role_names])
        self._generate_report_window("User Access Report",
                                      ["Username", "Name", "Department", "Status", "Roles"], rows)

    def _report_mfa_compliance(self):
        users = self.db.get_users(status_filter='active')
        rows = []
        for u in users:
            if not u['mfa_enabled']:
                roles = self.db.get_user_roles(u['id'])
                max_risk = 'low'
                for r in roles:
                    if r['risk_level'] == 'critical': max_risk = 'critical'
                    elif r['risk_level'] == 'high' and max_risk != 'critical': max_risk = 'high'
                    elif r['risk_level'] == 'medium' and max_risk in ('low',): max_risk = 'medium'
                rows.append([u['username'], u['display_name'], u['department'], max_risk.upper(), 'NO'])
        rows.sort(key=lambda r: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(r[3], 4))
        self._generate_report_window("MFA Compliance Report",
                                      ["Username", "Name", "Department", "Max Risk", "MFA"], rows)

    def _report_privileged_access(self):
        rows = []
        users = self.db.get_users(status_filter='active')
        for u in users:
            roles = self.db.get_user_roles(u['id'])
            priv_roles = [r for r in roles if r['risk_level'] in ('high', 'critical')]
            for r in priv_roles:
                rows.append([u['username'], u['display_name'], r['name'], r['risk_level'].upper(),
                           'Yes' if u['mfa_enabled'] else 'NO'])
        self._generate_report_window("Privileged Access Report",
                                      ["Username", "Name", "Role", "Risk Level", "MFA"], rows)

    def _report_inactive_users(self):
        users = self.db.get_users()
        rows = [[u['username'], u['display_name'], u['department'], u['status'].upper(), u['last_login'] or 'Never']
                for u in users if u['status'] in ('inactive', 'locked', 'pending_review')]
        self._generate_report_window("Inactive Users Report",
                                      ["Username", "Name", "Department", "Status", "Last Login"], rows)

    def _report_role_summary(self):
        roles = self.db.get_roles()
        rows = []
        for r in roles:
            members = self.db.get_role_users(r['id'])
            rows.append([r['name'], r['risk_level'].upper(), str(len(members)),
                        'Yes' if r['requires_mfa'] else 'No', f"{r['max_session_hours']}h"])
        self._generate_report_window("Role Summary Report",
                                      ["Role", "Risk Level", "Members", "MFA Required", "Max Session"], rows)

    def _report_audit_summary(self):
        entries = self.db.get_audit_log(limit=500)
        rows = [[e['timestamp'][:19], e['severity'].upper(), e['actor'], e['action'],
                e['target_name'] or '', e['details'] or ''] for e in entries]
        self._generate_report_window("Audit Summary",
                                      ["Timestamp", "Severity", "Actor", "Action", "Target", "Details"], rows)


if __name__ == "__main__":
    app = SecureAccessApp()
    app.mainloop()


