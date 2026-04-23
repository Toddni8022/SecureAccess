"""
Authenticated launcher for SecureAccess.

Run this instead of app.py when you want the desktop app protected by the
security core:

    python secure_launcher.py

Default demo bootstrap:
- username: admin
- password: SecureAccess!ChangeMe1

For a safer first run, set SECUREACCESS_BOOTSTRAP_PASSWORD before launch.
"""

from __future__ import annotations

import customtkinter as ctk
from tkinter import messagebox

from app import COLORS, SecureAccessApp
from database import Database
from security_core import SecurityService


class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.db = Database()
        self.security = SecurityService(self.db)
        self.security.bootstrap_admin_password()
        self.authenticated_user = None
        self.session_id = None

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("SecureAccess Login")
        self.geometry("440x360")
        self.resizable(False, False)

        card = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=16)
        card.pack(fill="both", expand=True, padx=30, pady=30)

        ctk.CTkLabel(card, text="🛡️", font=ctk.CTkFont(size=42)).pack(pady=(24, 4))
        ctk.CTkLabel(card, text="SecureAccess", font=ctk.CTkFont(size=24, weight="bold")).pack()
        ctk.CTkLabel(
            card,
            text="Sign in to manage access reviews, users, roles, and audit logs.",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_dim"],
            wraplength=330,
        ).pack(pady=(4, 18))

        self.username = ctk.CTkEntry(card, placeholder_text="Username", width=310)
        self.username.pack(pady=6)
        self.password = ctk.CTkEntry(card, placeholder_text="Password", show="*", width=310)
        self.password.pack(pady=6)
        self.password.bind("<Return>", lambda _event: self.login())

        ctk.CTkButton(
            card,
            text="Sign in",
            fg_color=COLORS["accent_green"],
            hover_color="#00a884",
            command=self.login,
            width=310,
        ).pack(pady=(16, 4))

        ctk.CTkLabel(
            card,
            text="Demo admin: admin / SecureAccess!ChangeMe1",
            font=ctk.CTkFont(size=10),
            text_color=COLORS["text_dim"],
        ).pack(pady=(8, 0))

    def login(self):
        result = self.security.authenticate(self.username.get().strip(), self.password.get())
        if not result.success or result.user is None:
            messagebox.showerror("Login failed", result.message)
            return

        self.authenticated_user = result.user
        self.session_id = self.security.create_session(result.user)
        self.destroy()


def main():
    login = LoginWindow()
    login.mainloop()

    if login.authenticated_user is None:
        return

    app = SecureAccessApp()
    app.current_user = login.authenticated_user
    app.security = login.security
    app.session_id = login.session_id
    app.title(f"SecureAccess — signed in as {login.authenticated_user['username']}")
    app.mainloop()


if __name__ == "__main__":
    main()
