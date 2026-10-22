#!/usr/bin/env python3
"""ARAP desktop client. Requires Python 3 with Tk and the arap CLI."""
from __future__ import annotations

import ipaddress
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Callable, TypeVar, cast

APP_TITLE = "ARAP — Amateur Radio Authentication Profile"
T = TypeVar("T")


def find_arap_cli() -> str:
    executable = "arap.exe" if os.name == "nt" else "arap"
    script_dir = Path(__file__).resolve().parent
    executable_dir = Path(sys.executable).resolve().parent
    candidates = (
        script_dir / executable,
        script_dir.parent / executable,
        script_dir.parent / "bin" / executable,
        executable_dir / executable,
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return shutil.which("arap") or ""


def find_tqsl_helper() -> str:
    configured = os.environ.get("ARAP_TQSL_HELPER", "").strip()
    if configured and Path(configured).is_file():
        return configured
    cli = find_arap_cli()
    if cli:
        suffix = ".exe" if os.name == "nt" else ""
        adjacent = Path(cli).resolve().with_name(f"arap-tqsl-sign{suffix}")
        if adjacent.is_file():
            return str(adjacent)
    return shutil.which("arap-tqsl-sign") or ""


class ARAPDesktop:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title(APP_TITLE)
        root.geometry("1000x760")
        root.minsize(840, 620)
        self.style = ttk.Style(root)
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")
        self.style.configure("Title.TLabel", font=("TkDefaultFont", 20, "bold"))
        self.style.configure("Sub.TLabel", foreground="#526174")
        root.protocol("WM_DELETE_WINDOW", self._request_close)
        self.cli = tk.StringVar(value=find_arap_cli())
        self.status = tk.StringVar(value="Local verification is available offline.")
        self._action_buttons: list[ttk.Button] = []
        self._scroll_canvases: dict[str, tk.Canvas] = {}
        self._busy = False
        self._build()

    def _build(self) -> None:
        shell = ttk.Frame(self.root, padding=18)
        shell.pack(fill="both", expand=True)
        header = ttk.Frame(shell)
        header.pack(fill="x", pady=(0, 14))
        ttk.Label(header, text="ARAP", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Sign and verify radio content with portable COSE proofs.", style="Sub.TLabel").pack(anchor="w", pady=(2, 8))
        clirow = ttk.Frame(header)
        clirow.pack(fill="x")
        ttk.Label(clirow, text="ARAP CLI", width=12).pack(side="left")
        ttk.Entry(clirow, textvariable=self.cli).pack(side="left", fill="x", expand=True)
        ttk.Button(clirow, text="Browse…", command=self.pick_cli).pack(side="left", padx=(8, 0))
        ttk.Button(clirow, text="About", command=self.show_about).pack(side="left", padx=(8, 0))
        ttk.Button(clirow, text="Setup diagnostics", command=self.show_setup_diagnostics).pack(side="left", padx=(8, 0))
        self.tabs = ttk.Notebook(shell)
        self.tabs.pack(fill="both", expand=True)
        self._workflow_tab()
        self._key_tab()
        self._sign_tab()
        self._pixelqso_tab()
        self._verify_tab()
        self._server_tab()
        self._verify_reference_tab()
        self._challenge_tab()
        ttk.Separator(shell).pack(fill="x", pady=(10, 6))
        ttk.Label(shell, textvariable=self.status, style="Sub.TLabel").pack(anchor="w")

    def _request_close(self) -> None:
        if self._busy:
            self.status.set("Wait for the current action to finish before closing ARAP.")
            return
        self.root.destroy()

    def show_about(self) -> None:
        manifest = Path(__file__).resolve().with_name("BUILD-MANIFEST.txt")
        details: dict[str, str] = {}
        if manifest.is_file():
            for line in manifest.read_text(encoding="utf-8").splitlines():
                if ": " in line:
                    key, value = line.split(": ", 1)
                    details[key] = value
        if details:
            version = details.get("ARAP version", "unknown")
            commit = details.get("Git base commit", "unknown")
            tqsl = details.get("TQSL/TQSLLIB version", "not included")
        else:
            try:
                result = subprocess.run(
                    [self.cli.get().strip(), "version", "--json"],
                    capture_output=True, text=True, timeout=5, check=True,
                )
                info = json.loads(result.stdout)
                version, commit = info.get("version", "unknown"), info.get("commit", "unknown")
                tqsl = "not reported by this development build"
            except Exception:
                version, commit, tqsl = "development build", "unknown", "not included"
        message = (
            f"ARAP desktop {version}\nSource commit: {commit}\n"
            f"TQSL/TQSLLIB: {tqsl}\n\n"
            "LoTW/TQSL enrollment is experimental and uses TQSL's legacy RSA-SHA1 signing API."
        )
        messagebox.showinfo("About ARAP", message, parent=self.root)

    def setup_diagnostics_text(self) -> str:
        rows = [f"Python: {sys.version.split()[0]}",
                f"Tk: {self.root.tk.call('info', 'patchlevel')}"]
        executable = self.cli.get().strip()
        if not executable or not Path(executable).is_file():
            rows.append("ARAP CLI: missing; use Browse to select the adjacent arap executable.")
        else:
            try:
                result = subprocess.run([executable, "version", "--json"], capture_output=True,
                                        text=True, timeout=5, check=True)
                info = json.loads(result.stdout)
                rows.append(f"ARAP CLI: {executable} (version {info.get('version', 'unknown')}, commit {info.get('commit', 'unknown')})")
            except Exception as exc:
                rows.append(f"ARAP CLI: could not run ({exc}); check the selected executable and permissions.")

        helper = self.enrollment_tqsl_helper.get().strip()
        if not helper or not Path(helper).is_file():
            rows.append("TQSL helper: not found; use a native enrollment bundle or set ARAP_TQSL_HELPER.")
        else:
            helper_path = Path(helper).resolve()
            runtime_files = ("config.xml",) if os.name == "nt" or sys.platform == "darwin" else (
                "libtqsllib.so", "config.xml"
            )
            missing = [name for name in runtime_files
                       if not (helper_path.parent / name).is_file()]
            try:
                result = subprocess.run([helper], capture_output=True, text=True,
                                        timeout=5, check=False)
                runtime_ok = result.returncode == 2 and "valid --callsign is required" in result.stderr
            except OSError as exc:
                runtime_ok = False
                runtime_error = str(exc)
            else:
                runtime_error = "required shared libraries could not be loaded"
            state = "ready" if runtime_ok and not missing else "incomplete"
            rows.append(f"TQSL helper: {helper_path} ({state})")
            if missing:
                rows.append("  Missing adjacent helper resources: " + ", ".join(missing))
            if not runtime_ok:
                rows.append(f"  Helper runtime check failed: {runtime_error}")

        tqsl = shutil.which("tqsl")
        if tqsl:
            try:
                result = subprocess.run([tqsl, "--version"], capture_output=True, text=True,
                                        timeout=5, check=True)
                tqsl_version = (result.stdout or result.stderr).strip().replace("\n", " ")
                rows.append(f"TQSL command: {tqsl_version} ({tqsl})")
            except Exception as exc:
                rows.append(f"TQSL command: found at {tqsl}, but version check failed ({exc})")
        else:
            rows.append("TQSL command: not found in PATH; install TQSL before enrollment")
        data_dir = Path.home() / ".tqsl"
        rows.append(f"TQSL user data: {data_dir} ({'found' if data_dir.is_dir() else 'not found'})")
        rows.append("A current issued Callsign Certificate and its password are required for enrollment signing.")
        rows.append("Enrollment is experimental; it is not an ARRL-approved login or LoTW transaction.")
        return "\n".join(rows)

    def show_setup_diagnostics(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("ARAP setup diagnostics")
        dialog.transient(self.root)
        dialog.geometry("760x430")
        text = tk.Text(dialog, wrap="word", height=18, width=90)
        text.pack(fill="both", expand=True, padx=12, pady=12)
        text.insert("1.0", self.setup_diagnostics_text())
        text.configure(state="disabled")

        def copy_report() -> None:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.setup_diagnostics_text())
            self.status.set("Setup diagnostics copied. Review and redact personal paths before sharing.")

        ttk.Button(dialog, text="Copy diagnostics", command=copy_report).pack(anchor="e", padx=12, pady=(0, 12))

    def _form(self, tab: ttk.Frame) -> ttk.Frame:
        viewport = ttk.Frame(tab)
        viewport.pack(fill="both", expand=True)
        canvas = tk.Canvas(viewport, highlightthickness=0, borderwidth=0, yscrollincrement=20)
        scrollbar = ttk.Scrollbar(viewport, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        body = ttk.Frame(canvas, padding=18)
        window = canvas.create_window((0, 0), window=body, anchor="nw")
        self._scroll_canvases[str(tab)] = canvas
        body.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(window, width=event.width))

        def scroll_wheel(event: tk.Event) -> str:
            if getattr(event, "num", None) == 4:
                units = -3
            elif getattr(event, "num", None) == 5:
                units = 3
            else:
                delta = getattr(event, "delta", 0)
                units = -int(delta / 120) if abs(delta) >= 120 else (-1 if delta > 0 else 1 if delta < 0 else 0)
            target = event.widget if isinstance(event.widget, tk.Text) else canvas
            if units:
                target.yview_scroll(units, "units")
            return "break"

        def bind_wheel(_event: tk.Event) -> None:
            self.root.bind_all("<MouseWheel>", scroll_wheel)
            self.root.bind_all("<Button-4>", scroll_wheel)
            self.root.bind_all("<Button-5>", scroll_wheel)

        def unbind_wheel(_event: tk.Event) -> None:
            self.root.unbind_all("<MouseWheel>")
            self.root.unbind_all("<Button-4>")
            self.root.unbind_all("<Button-5>")

        canvas.bind("<Enter>", bind_wheel)
        canvas.bind("<Leave>", unbind_wheel)
        body.columnconfigure(1, weight=1)
        return body

    def _workflow_tab(self) -> None:
        tab = ttk.Frame(self.tabs, padding=20)
        self.tabs.add(tab, text="Start here")
        ttk.Label(tab, text="ARAP application workflows", font=("TkDefaultFont", 15, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 6)
        )
        ttk.Label(
            tab,
            text="Content signing and peer authentication are separate operations. Your application carries files over its own transport and decides which identities and purposes it trusts.",
            style="Sub.TLabel", wraplength=760, justify="left",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 14))
        steps = (
            ("1. Identity and trust", "Create an encrypted ARAP key and add public-key trust for the intended callsign and purpose.", "Keys & Trust"),
            ("2. Sign content", "Create a detached proof over the exact file bytes, media type, and application context.", "Sign content"),
            ("3. Verify content", "Check the proof against the original file, expected context, public key, and your trust policy.", "Verify"),
            ("4. Authenticate a peer", "Requester/verifier issues and stores a challenge; responder signs it; requester/verifier checks and consumes it once.", "Challenge"),
            ("PixelQSO cards", "Sign or verify canonical saved-card data. Frame 2 requires its matching first-frame card.", "PixelQSO cards"),
        )
        for row, (title, description, destination) in enumerate(steps, start=2):
            ttk.Label(tab, text=title, font=("TkDefaultFont", 10, "bold")).grid(
                row=row, column=0, sticky="nw", padx=(0, 12), pady=8
            )
            ttk.Label(tab, text=description, wraplength=560, justify="left").grid(
                row=row, column=1, sticky="ew", pady=8
            )
            ttk.Button(tab, text="Open", command=lambda name=destination: self.select_tab(name)).grid(
                row=row, column=2, sticky="e", padx=(12, 0), pady=8
            )
        ttk.Separator(tab).grid(row=7, column=0, columnspan=3, sticky="ew", pady=12)
        ttk.Label(
            tab,
            text="Callsign Certificate enrollment is in Keys & Trust. It binds a fresh challenge to the chosen ARAP key fingerprint and verifier audience; choose a matching current TQSL certificate serial before signing. This RSA-SHA1 assertion provides authentication evidence for ARAP; it is not an ARRL-approved login or LoTW transaction.",
            style="Sub.TLabel", wraplength=760, justify="left",
        ).grid(row=8, column=0, columnspan=3, sticky="w")
        tab.columnconfigure(1, weight=1)

    def select_tab(self, label: str) -> None:
        for tab_id in self.tabs.tabs():
            if self.tabs.tab(tab_id, "text") == label:
                self.tabs.select(tab_id)
                return
        raise ValueError(f"ARAP tab is unavailable: {label}")

    def _entry(self, parent: ttk.Frame, row: int, label: str, key: str, value: str = "", browse: str | None = None, secret: bool = False) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=5, padx=(0, 14))
        var = tk.StringVar(value=value)
        entry = ttk.Entry(parent, textvariable=var, show="•" if secret else "")
        entry.grid(row=row, column=1, sticky="ew", pady=5)
        setattr(self, key, var)
        if browse:
            mode = browse
            command = lambda: self.pick_file(var, mode)
            ttk.Button(parent, text="Browse…", command=command).grid(row=row, column=2, padx=(8, 0), pady=5)
        return entry

    def _action(self, parent: ttk.Frame, row: int, text: str, command) -> None:
        button = ttk.Button(parent, text=text, command=command)
        button.grid(row=row, column=1, sticky="w", pady=(12, 6))
        self._action_buttons.append(button)

    def _key_tab(self) -> None:
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Keys & Trust")
        body = self._form(tab)
        ttk.Label(body, text="Create an identity-neutral Ed25519 key. New private keys use the standard armored age format with passphrase encryption; older unencrypted PKCS#8 keys remain readable. A callsign is authorized separately with a local trust binding.", style="Sub.TLabel", wraplength=650).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
        self._entry(body, 1, "Private key output", "key_private", browse="save")
        self._entry(body, 2, "Public key output", "key_public", browse="save")
        self._action(body, 3, "Generate key pair", self.generate_keys)
        ttk.Separator(body).grid(row=4, column=0, columnspan=3, sticky="ew", pady=16)
        self._entry(body, 5, "Trust store", "trust_path", browse="save")
        self._entry(body, 6, "Public key", "trust_public", browse="open")
        self._entry(body, 7, "Authorized callsign", "trust_call")
        ttk.Label(body, text="Authorized purpose").grid(row=8, column=0, sticky="w", pady=5, padx=(0, 14))
        self.trust_purpose = tk.StringVar(value="content-signature")
        self.trust_purpose_picker = ttk.Combobox(
            body,
            textvariable=self.trust_purpose,
            values=("content-signature", "challenge-response"),
            state="readonly",
        )
        self.trust_purpose_picker.grid(row=8, column=1, sticky="ew", pady=5)
        self._action(body, 9, "Add / re-enable local trust binding", self.add_trust)
        self._action(body, 10, "Show local trust store", self.show_trust)
        ttk.Separator(body).grid(row=11, column=0, columnspan=3, sticky="ew", pady=12)
        ttk.Label(body, text="Disable a trusted key", font=("TkDefaultFont", 11, "bold")).grid(row=12, column=0, columnspan=2, sticky="w", pady=(0, 4))
        self._entry(body, 13, "Binding callsign", "trust_disable_call")
        self._entry(body, 14, "Key fingerprint", "trust_disable_key")
        self._action(body, 15, "Disable local trust binding", self.disable_trust)
        ttk.Separator(body).grid(row=16, column=0, columnspan=3, sticky="ew", pady=16)
        ttk.Label(body, text="LoTW enrollment records", font=("TkDefaultFont", 11, "bold")).grid(row=17, column=0, columnspan=2, sticky="w", pady=(0, 4))
        ttk.Label(body, text="Inspect or disable persisted enrollment bindings. Enrollment uses a fresh challenge and TQSL signing; it does not create or submit a QSO.", style="Sub.TLabel", wraplength=650).grid(row=18, column=0, columnspan=3, sticky="w", pady=(0, 8))
        self._entry(body, 19, "Enrollment database", "enrollment_path", browse="save")
        self._action(body, 20, "Show enrollment bindings", self.show_enrollment)
        self._entry(body, 21, "Enrollment callsign", "enrollment_disable_call")
        self._entry(body, 22, "Enrollment key fingerprint", "enrollment_disable_key")
        self._action(body, 23, "Disable enrollment binding", self.disable_enrollment)
        ttk.Separator(body).grid(row=24, column=0, columnspan=3, sticky="ew", pady=16)
        ttk.Label(body, text="Issue LoTW enrollment challenge", font=("TkDefaultFont", 11, "bold")).grid(row=25, column=0, columnspan=2, sticky="w", pady=(0, 4))
        ttk.Label(body, text="Creates a short-lived challenge bound to the selected Ed25519 key. The responder signs those challenge bytes with TQSL and the matching ARAP key.", style="Sub.TLabel", wraplength=650).grid(row=26, column=0, columnspan=3, sticky="w", pady=(0, 8))
        self._entry(body, 27, "Verifier audience", "enrollment_audience")
        self._entry(body, 28, "Callsign to enroll", "enrollment_issue_call")
        self._entry(body, 29, "ARAP Ed25519 public key", "enrollment_issue_public", browse="open")
        self._entry(body, 30, "Challenge file output", "enrollment_issue_out", browse="save")
        self._entry(body, 31, "Lifetime in seconds (1–300)", "enrollment_issue_lifetime", "120")
        self._action(body, 32, "Create enrollment challenge", self.issue_enrollment)
        ttk.Separator(body).grid(row=33, column=0, columnspan=3, sticky="ew", pady=16)
        ttk.Label(body, text="Sign an enrollment challenge with TQSL", font=("TkDefaultFont", 11, "bold")).grid(row=34, column=0, columnspan=2, sticky="w", pady=(0, 4))
        ttk.Label(body, text="Uses the native TQSLLIB helper to sign the challenge in memory. TQSL's station private key is not exported. The response is an experimental RSA/SHA-1 enrollment assertion, not a QSO upload or ARRL-approved LoTW transaction.", style="Sub.TLabel", wraplength=650).grid(row=35, column=0, columnspan=3, sticky="w", pady=(0, 8))
        self._entry(body, 36, "Enrollment challenge file", "enrollment_respond_request", browse="open")
        self._entry(body, 37, "ARAP Ed25519 private key", "enrollment_respond_key", browse="open")
        self._entry(body, 38, "Signed response output", "enrollment_respond_out", browse="save")
        self._entry(body, 39, "TQSL native helper (optional)", "enrollment_tqsl_helper", find_tqsl_helper(), browse="open")
        self._entry(body, 40, "TQSL certificate serial (optional)", "enrollment_tqsl_serial")
        ttk.Button(body, text="List matching certificates", command=self.list_enrollment_certificates).grid(row=40, column=2, padx=(8, 0), pady=5)
        self.enrollment_sign_allow_legacy = tk.BooleanVar(value=False)
        tk.Checkbutton(body, text="Allow TQSL's legacy RSA/SHA-1 signature for this enrollment assertion", variable=self.enrollment_sign_allow_legacy, wraplength=650, justify="left").grid(row=41, column=0, columnspan=3, sticky="w", pady=(8, 4))
        self._action(body, 42, "Sign enrollment challenge", self.respond_enrollment)
        ttk.Separator(body).grid(row=43, column=0, columnspan=3, sticky="ew", pady=16)
        ttk.Label(body, text="Verify enrollment response", font=("TkDefaultFont", 11, "bold")).grid(row=44, column=0, columnspan=2, sticky="w", pady=(0, 4))
        ttk.Label(body, text="Checks the certificate chain, callsign, challenge signatures and live LoTW status, then records an accepted binding in the enrollment database.", style="Sub.TLabel", wraplength=650).grid(row=45, column=0, columnspan=3, sticky="w", pady=(0, 8))
        self._entry(body, 46, "Signed response file", "enrollment_verify_response", browse="open")
        self._entry(body, 47, "Expected verifier audience", "enrollment_verify_audience")
        self._entry(body, 48, "ARRL roots PEM override (optional)", "enrollment_verify_roots", browse="open")
        self._entry(body, 49, "Maximum status age in hours", "enrollment_verify_status_age", "24")
        self.enrollment_allow_legacy_rsa_sha1 = tk.BooleanVar(value=False)
        tk.Checkbutton(
            body,
            text="Accept TQSL's legacy RSA/SHA-1 signature for this enrollment assertion",
            variable=self.enrollment_allow_legacy_rsa_sha1,
            wraplength=650,
            justify="left",
        ).grid(row=50, column=0, columnspan=3, sticky="w", pady=(8, 4))
        self._action(body, 51, "Verify response and record binding", self.verify_enrollment)
        ttk.Separator(body).grid(row=52, column=0, columnspan=3, sticky="ew", pady=16)
        ttk.Label(body, text="Refresh accepted certificate status", font=("TkDefaultFont", 11, "bold")).grid(row=53, column=0, columnspan=2, sticky="w", pady=(0, 4))
        ttk.Label(body, text="Uses the saved accepted response to revalidate the same certificate and key, then obtains fresh status from LoTW. This does not enable a disabled binding.", style="Sub.TLabel", wraplength=650).grid(row=54, column=0, columnspan=3, sticky="w", pady=(0, 8))
        self._entry(body, 55, "Previously accepted response", "enrollment_refresh_response", browse="open")
        self._entry(body, 56, "Bound callsign", "enrollment_refresh_call")
        self._entry(body, 57, "Bound key fingerprint", "enrollment_refresh_key")
        self._action(body, 58, "Refresh LoTW certificate status", self.refresh_enrollment)

    def _sign_tab(self) -> None:
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Sign content")
        body = self._form(tab)
        ttk.Label(body, text="The proof signs the exact file bytes. Keep the proof beside the content or publish it to a keyserver.", style="Sub.TLabel", wraplength=650).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
        self._entry(body, 1, "Callsign", "sign_call")
        self._entry(body, 2, "Private key", "sign_key", browse="open")
        self._entry(body, 3, "Content file", "sign_input", browse="open")
        self._entry(body, 4, "Media type", "sign_media", "application/octet-stream")
        self._entry(body, 5, "Application context", "sign_context")
        self._entry(body, 6, "Output proof", "sign_output", browse="save")
        self._action(body, 7, "Create signed proof", self.sign_content)

    def _verify_tab(self) -> None:
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Verify")
        body = self._form(tab)
        ttk.Label(body, text="Verification checks the signature, exact content bytes, expected application context, and your local callsign/key trust entry.", style="Sub.TLabel", wraplength=700).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
        self._entry(body, 1, "Proof file", "verify_proof", browse="open")
        self._entry(body, 2, "Content file", "verify_input", browse="open")
        self._entry(body, 3, "Public key", "verify_public", browse="open")
        self._entry(body, 4, "Trust store", "verify_trust", browse="open")
        self._entry(body, 5, "Expected media type", "verify_media", "application/octet-stream")
        self._entry(body, 6, "Expected context", "verify_context")
        self._entry(body, 7, "Expected signer (optional)", "verify_call")
        self._action(body, 8, "Verify proof", self.verify_content)
        self.result = tk.Text(body, height=9, wrap="word", state="disabled", background="#f4f7fb", relief="flat")
        self.result.grid(row=9, column=0, columnspan=3, sticky="nsew", pady=(12, 0))
        body.rowconfigure(9, weight=1)

    def _pixelqso_tab(self) -> None:
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="PixelQSO cards")
        body = self._form(tab)
        ttk.Label(body, text="Sign or verify a saved PixelQSO card. ARAP signs its canonical card fields and ignores editor-only layers; the card file is not modified.", style="Sub.TLabel", wraplength=700).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
        self._entry(body, 1, "Card JSON to sign", "pixelqso_sign_card", browse="open")
        self._entry(body, 2, "Private key", "pixelqso_sign_key", browse="open")
        self._entry(body, 3, "First frame (frame 2 only)", "pixelqso_sign_first", browse="open")
        self._entry(body, 4, "Output proof", "pixelqso_sign_proof", browse="save")
        self._action(body, 5, "Sign PixelQSO card", self.sign_pixelqso)
        ttk.Separator(body).grid(row=6, column=0, columnspan=3, sticky="ew", pady=12)
        self._entry(body, 7, "Card JSON to verify", "pixelqso_verify_card", browse="open")
        self._entry(body, 8, "First frame (frame 2 only)", "pixelqso_verify_first", browse="open")
        self._entry(body, 9, "Proof", "pixelqso_verify_proof", browse="open")
        self._entry(body, 10, "Public key", "pixelqso_verify_public", browse="open")
        self._entry(body, 11, "Trust store", "pixelqso_verify_trust", browse="open")
        self._action(body, 12, "Verify PixelQSO card", self.verify_pixelqso)
        self.pixelqso_result = tk.Text(body, height=8, wrap="word", state="disabled", background="#f4f7fb", relief="flat")
        self.pixelqso_result.grid(row=13, column=0, columnspan=3, sticky="nsew", pady=(12, 0))
        body.rowconfigure(13, weight=1)

    def _server_tab(self) -> None:
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Keyserver")
        body = self._form(tab)
        ttk.Label(body, text="The keyserver stores public objects by cryptographic hash. Published keys and proofs remain untrusted until verified under your local policy.", style="Sub.TLabel", wraplength=700).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
        ttk.Label(body, text="Certificates can be published as untrusted identity artifacts; this ARAP profile signs and verifies proofs with Ed25519 keys.", style="Sub.TLabel", wraplength=700).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 8))
        self._entry(body, 2, "Keyserver URLs (comma or semicolon separated)", "server_url", "https://")
        ttk.Label(body, text="Fetches check every configured resolver. Publishing sends to the first URL.", style="Sub.TLabel", wraplength=650).grid(row=3, column=1, sticky="w", pady=(0, 5))
        self._entry(body, 4, "Upload token", "server_token", secret=True)
        self._entry(body, 5, "Public key or certificate to publish", "server_public", browse="open")
        self._action(body, 6, "Publish public key", self.publish_key)
        self._entry(body, 7, "Proof to publish", "server_proof", browse="open")
        self._action(body, 8, "Publish proof and show short reference", self.publish_proof)
        self.reference = tk.StringVar(value="")
        ttk.Label(body, text="Short reference").grid(row=9, column=0, sticky="w", pady=5, padx=(0, 14))
        ttk.Entry(body, textvariable=self.reference).grid(row=9, column=1, sticky="ew", pady=5)
        self._entry(body, 10, "Fetch key fingerprint", "fetch_fingerprint")
        self._entry(body, 11, "Save key or certificate as", "fetch_output", browse="save")
        self._action(body, 12, "Fetch public key", self.fetch_key)
        ttk.Separator(body).grid(row=13, column=0, columnspan=3, sticky="ew", pady=12)
        self._entry(body, 14, "Proof hash or AR1 reference", "fetch_proof_ref")
        self._entry(body, 15, "Save proof as", "fetch_proof_output", browse="save")
        self._action(body, 16, "Resolve and fetch proof", self.fetch_proof)

    def _verify_reference_tab(self) -> None:
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Verify reference")
        body = self._form(tab)
        ttk.Label(body, text="Resolve an AR1 reference and verify the proof against local content and trust in one step.", style="Sub.TLabel", wraplength=700).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
        self._entry(body, 1, "Keyserver URLs", "ref_server_url", "https://")
        self._entry(body, 2, "Proof hash or AR1 reference", "ref_reference")
        self._entry(body, 3, "Content file", "ref_content", browse="open")
        self._entry(body, 4, "Public key", "ref_public", browse="open")
        self._entry(body, 5, "Local trust store", "ref_trust", browse="open")
        self._entry(body, 6, "Expected media type", "ref_media", "application/octet-stream")
        self._entry(body, 7, "Expected context", "ref_context")
        self._entry(body, 8, "Expected signer (optional)", "ref_call")
        self._action(body, 9, "Resolve and verify", self.verify_reference)
        self.ref_result = tk.Text(body, height=10, wrap="word", state="disabled", background="#f4f7fb", relief="flat")
        self.ref_result.grid(row=10, column=0, columnspan=3, sticky="nsew", pady=(12, 0))
        body.rowconfigure(10, weight=1)

    def verify_reference(self) -> None:
        try:
            bases = self._validate_resolver_list(self.ref_server_url.get())
            reference = self.ref_reference.get().strip()
            content = self.ref_content.get().strip()
            public = self.ref_public.get().strip()
            trust = self.ref_trust.get().strip()
            media = self.ref_media.get().strip()
            context = self.ref_context.get().strip()
            if not all((reference, content, public, trust, media, context)):
                raise ValueError("Complete the reference, content, public key, trust store, media type and context fields.")
            args = ["verify-ref"]
            for base in bases:
                args.extend(["--server", base])
            args.extend(["--reference", reference, "--input", content, "--public-key", public,
                         "--trust-store", trust, "--expect-media-type", media, "--expect-context", context])
            call = self.ref_call.get().strip()
            if call:
                args.extend(["--expect-callsign", call])
            _, output = self.run_cli(args, (0, 1, 3))
            result = json.loads(output)
            self.ref_result.configure(state="normal")
            self.ref_result.delete("1.0", "end")
            self.ref_result.insert("1.0", json.dumps(result, indent=2))
            self.ref_result.configure(state="disabled")
            state = result.get("overall_policy", "rejected")
            self.status.set(f"Reference verification: {state} — {result.get('reason', 'checks completed')}")
        except Exception as exc:
            self._error(exc)

    def _validate_resolver_list(self, raw: str) -> list[str]:
        bases = [item.strip().rstrip("/") for item in raw.replace(";", ",").split(",") if item.strip()]
        if not bases or len(bases) > 8:
            raise ValueError("Enter between one and eight keyserver URLs.")
        return list(dict.fromkeys(self._validate_server_base(base) for base in bases))

    def _challenge_tab(self) -> None:
        tab = ttk.Frame(self.tabs)
        self.tabs.add(tab, text="Challenge")
        body = self._form(tab)
        ttk.Label(body, text="The requester also acts as verifier: issue and store the request, send it to the named responder, then verify and consume the response once. The responder signs the request with its ARAP key. Exchange request and response files using your application's transport.", style="Sub.TLabel", wraplength=720, justify="left").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
        ttk.Label(body, text="Requester / verifier — issue and store", font=("TkDefaultFont", 11, "bold")).grid(row=1, column=0, sticky="w", pady=(4, 2))
        self._entry(body, 2, "Requester callsign", "challenge_requester")
        self._entry(body, 3, "Responder callsign", "challenge_responder")
        self._entry(body, 4, "Replay database", "challenge_store", browse="save")
        self._entry(body, 5, "Request file output", "challenge_request_out", browse="save")
        self._action(body, 6, "Create and record challenge", self.issue_challenge)
        ttk.Separator(body).grid(row=7, column=0, columnspan=3, sticky="ew", pady=9)
        ttk.Label(body, text="Responder — sign the request", font=("TkDefaultFont", 11, "bold")).grid(row=8, column=0, sticky="w", pady=(2, 2))
        self._entry(body, 9, "Challenge request", "challenge_in_request", browse="open")
        self._entry(body, 10, "Responder callsign", "challenge_signer")
        self._entry(body, 11, "Responder private key", "challenge_private", browse="open")
        self._entry(body, 12, "Response proof output", "challenge_response_out", browse="save")
        self._action(body, 13, "Sign challenge response", self.respond_challenge)
        ttk.Separator(body).grid(row=14, column=0, columnspan=3, sticky="ew", pady=9)
        ttk.Label(body, text="Requester / verifier — verify and consume once", font=("TkDefaultFont", 11, "bold")).grid(row=15, column=0, sticky="w", pady=(2, 2))
        self._entry(body, 16, "Original challenge", "challenge_verify_request", browse="open")
        self._entry(body, 17, "Response proof", "challenge_verify_response", browse="open")
        self._entry(body, 18, "Responder public key", "challenge_public", browse="open")
        self._entry(body, 19, "Local trust store", "challenge_trust", browse="open")
        self._entry(body, 20, "LoTW enrollment database (optional)", "challenge_enrollment", browse="save")
        self._entry(body, 21, "Requester callsign", "challenge_expected_requester")
        self._action(body, 22, "Verify once and consume challenge", self.verify_challenge)

    def pick_cli(self) -> None:
        path = filedialog.askopenfilename(title="Select the arap executable")
        if path: self.cli.set(path)

    def pick_file(self, variable: tk.StringVar, mode: str) -> None:
        if mode == "open": path = filedialog.askopenfilename()
        else: path = filedialog.asksaveasfilename()
        if path: variable.set(path)

    def run_cli(self, args: list[str], accept: tuple[int, ...] = (0,), env: dict[str, str] | None = None, input_text: str | None = None) -> tuple[int, str]:
        executable = self.cli.get().strip()
        if not executable: raise RuntimeError("Select or install the arap CLI first.")
        def invoke() -> tuple[int, str]:
            result = subprocess.run([executable, *args], capture_output=True, text=True, timeout=300, env=env, input=input_text)
            output = result.stdout.strip() or result.stderr.strip()
            if result.returncode not in accept: raise RuntimeError(output or f"arap exited with {result.returncode}")
            return result.returncode, output
        return self._run_blocking(invoke, "Running ARAP command…")

    def _run_blocking(self, operation: Callable[[], T], status: str) -> T:
        if self._busy:
            raise RuntimeError("Another ARAP action is already running.")
        self._busy = True
        previous_states = [str(button.cget("state")) for button in self._action_buttons]
        for button in self._action_buttons:
            button.configure(state="disabled")
        self.status.set(status)
        completed: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)
        finished = threading.Event()
        outcome: list[object] = []

        def worker() -> None:
            try:
                completed.put((True, operation()))
            except Exception as exc:
                completed.put((False, exc))

        action_thread = threading.Thread(target=worker, name="arap-desktop-action", daemon=True)

        def poll() -> None:
            try:
                succeeded, value = completed.get_nowait()
            except queue.Empty:
                self.root.after(25, poll)
                return
            action_thread.join()
            self._busy = False
            for button, state in zip(self._action_buttons, previous_states):
                button.configure(state=state)
            outcome.extend((succeeded, value))
            finished.set()

        self.root.after(25, poll)
        action_thread.start()
        while not finished.is_set():
            # Keep Tk responsive on its owning thread while the operation runs.
            self.root.update()
            finished.wait(0.01)
        if len(outcome) != 2:
            raise RuntimeError("The desktop closed before the ARAP action completed.")
        succeeded, value = outcome
        if not succeeded:
            if isinstance(value, BaseException):
                raise value
            raise RuntimeError(str(value))
        return cast(T, value)

    def _report(self, title: str, message: str) -> None:
        self.status.set(message.splitlines()[0][:140] if message else title)
        messagebox.showinfo(title, message or "Completed.", parent=self.root)

    def _error(self, exc: Exception) -> None:
        self.status.set("Action failed.")
        message = str(exc)
        if "unlock TQSL certificate" in message:
            message += "\n\nCheck the TQSL certificate password, selected serial, and that the certificate is current and enabled in TQSL."
        elif "TQSL native helper not found" in message:
            message += "\n\nUse a native enrollment bundle or select the helper with ARAP_TQSL_HELPER."
        messagebox.showerror("ARAP", message, parent=self.root)

    def _ask_passphrase(self, title: str, confirm: bool = False) -> str:
        prompt = "Create passphrase (at least 12 UTF-8 bytes):" if confirm else "Private-key passphrase (leave blank only for a legacy unencrypted key):"
        first = simpledialog.askstring(title, prompt, show="•", parent=self.root)
        if first is None:
            raise ValueError("Passphrase entry cancelled.")
        if confirm:
            second = simpledialog.askstring(title, "Confirm passphrase:", show="•", parent=self.root)
            if second is None:
                raise ValueError("Passphrase confirmation cancelled.")
            if first != second:
                raise ValueError("Passphrases do not match.")
        return first

    def generate_keys(self) -> None:
        try:
            private, public = self.key_private.get().strip(), self.key_public.get().strip()
            if not private or not public: raise ValueError("Enter paths for both key files.")
            passphrase = self._ask_passphrase("Protect new private key", confirm=True)
            if len(passphrase.encode("utf-8")) < 12: raise ValueError("Use a passphrase of at least 12 UTF-8 bytes.")
            self.run_cli(["keygen", "--private-key", private, "--public-key", public, "--passphrase-stdin"], input_text=f"{passphrase}\n{passphrase}\n")
            self._report("Keys created", f"Private key: {private}\nPublic key: {public}\n\nThe private key is encrypted in the age file format and created with owner-only permissions where supported. Keep the passphrase and backups safe; ARAP does not store the passphrase in an OS keychain.")
        except Exception as exc: self._error(exc)

    def sign_content(self) -> None:
        try:
            required = [self.sign_call.get(), self.sign_key.get(), self.sign_input.get(), self.sign_media.get(), self.sign_context.get(), self.sign_output.get()]
            if not all(x.strip() for x in required): raise ValueError("Complete every signing field.")
            passphrase = self._ask_passphrase("Unlock signing key")
            _, output = self.run_cli(["sign-content", "--key", required[1], "--callsign", required[0], "--input", required[2], "--media-type", required[3], "--context", required[4], "--out", required[5], "--passphrase-stdin"], input_text=passphrase + "\n")
            self._report("Proof created", f"Saved to {required[5]}\n\n{output}")
        except Exception as exc: self._error(exc)

    def verify_content(self) -> None:
        try:
            required = [self.verify_proof.get(), self.verify_input.get(), self.verify_public.get(), self.verify_trust.get(), self.verify_media.get(), self.verify_context.get()]
            if not all(x.strip() for x in required): raise ValueError("Complete the proof, content, key, trust store, media type and context fields.")
            args = ["verify-content", "--proof", required[0], "--input", required[1], "--public-key", required[2], "--trust-store", required[3], "--expect-media-type", required[4], "--expect-context", required[5]]
            if self.verify_call.get().strip(): args.extend(["--expect-callsign", self.verify_call.get().strip()])
            _, output = self.run_cli(args, (0, 1, 3))
            result = json.loads(output)
            self.result.configure(state="normal")
            self.result.delete("1.0", "end")
            self.result.insert("1.0", json.dumps(result, indent=2))
            self.result.configure(state="disabled")
            state = result.get("overall_policy", "rejected")
            self.status.set(f"Verification: {state} — {result.get('reason', 'checks passed')}")
        except Exception as exc: self._error(exc)

    def sign_pixelqso(self) -> None:
        try:
            card, key, proof = (self.pixelqso_sign_card.get().strip(),
                                self.pixelqso_sign_key.get().strip(),
                                self.pixelqso_sign_proof.get().strip())
            if not all((card, key, proof)):
                raise ValueError("Choose a card JSON file, private key, and proof output path.")
            args = ["sign-pixelqso", "--card", card, "--key", key, "--out", proof]
            passphrase = self._ask_passphrase("Unlock signing key")
            first = self.pixelqso_sign_first.get().strip()
            if first: args.extend(["--first-card", first])
            args.append("--passphrase-stdin")
            _, output = self.run_cli(args, input_text=passphrase + "\n")
            self._report("PixelQSO proof created", f"Proof saved to {proof}\n\n{output}")
        except Exception as exc: self._error(exc)

    def verify_pixelqso(self) -> None:
        try:
            card, first, proof, public, trust = (self.pixelqso_verify_card.get().strip(),
                                          self.pixelqso_verify_first.get().strip(),
                                          self.pixelqso_verify_proof.get().strip(),
                                          self.pixelqso_verify_public.get().strip(),
                                          self.pixelqso_verify_trust.get().strip())
            if not all((card, proof, public, trust)):
                raise ValueError("Choose a card, proof, public key, and local trust store.")
            args = ["verify-pixelqso", "--card", card, "--proof", proof,
                    "--public-key", public, "--trust-store", trust]
            if first: args.extend(["--first-card", first])
            _, output = self.run_cli(args, (0, 1, 3))
            result = json.loads(output)
            self.pixelqso_result.configure(state="normal")
            self.pixelqso_result.delete("1.0", "end")
            self.pixelqso_result.insert("1.0", json.dumps(result, indent=2))
            self.pixelqso_result.configure(state="disabled")
            state = result.get("overall_policy", "rejected")
            self.status.set(f"PixelQSO verification: {state} — {result.get('reason', 'checks passed')}")
        except Exception as exc: self._error(exc)

    def add_trust(self) -> None:
        try:
            required = [self.trust_path.get(), self.trust_public.get(), self.trust_call.get()]
            if not all(x.strip() for x in required): raise ValueError("Choose a trust store, public key and callsign.")
            purpose = self.trust_purpose.get().strip()
            if purpose not in ("content-signature", "challenge-response"): raise ValueError("Purpose must be content-signature or challenge-response.")
            self.run_cli(["trust", "add", "--store", required[0], "--public-key", required[1], "--callsign", required[2], "--purpose", purpose])
            self._report("Trust added", f"This computer now trusts {required[2].strip().upper()} for {purpose} under the selected local trust file.")
        except Exception as exc: self._error(exc)

    def show_trust(self) -> None:
        try:
            path = self.trust_path.get().strip()
            if not path: raise ValueError("Choose a trust store.")
            _, output = self.run_cli(["trust", "list", "--store", path])
            self._report("Local trust", output)
        except Exception as exc: self._error(exc)

    def disable_trust(self) -> None:
        try:
            store = self.trust_path.get().strip()
            callsign = self.trust_disable_call.get().strip()
            key_id = self.trust_disable_key.get().strip().lower()
            if not all((store, callsign, key_id)):
                raise ValueError("Choose a trust store and enter the binding callsign and full key fingerprint.")
            self.run_cli(["trust", "disable", "--store", store, "--callsign", callsign, "--key-id", key_id])
            self._report("Trust disabled", f"The local trust binding for {callsign.upper()} and {key_id} is disabled.")
        except Exception as exc: self._error(exc)

    def show_enrollment(self) -> None:
        try:
            path = self.enrollment_path.get().strip()
            if not path: raise ValueError("Choose an enrollment database.")
            _, output = self.run_cli(["enrollment", "list", "--store", path])
            bindings = json.loads(output)
            if not isinstance(bindings, list):
                raise ValueError("ARAP returned an invalid enrollment binding list.")
            self._report("LoTW enrollment records", self.format_enrollment_bindings(bindings))
        except Exception as exc: self._error(exc)

    @staticmethod
    def format_enrollment_bindings(bindings: list[dict[str, object]], now: int | None = None) -> str:
        if not bindings:
            return "No enrollment bindings are stored."
        observed_now = int(time.time()) if now is None else now

        def instant(value: object) -> str:
            try:
                timestamp = int(value)
                if timestamp <= 0:
                    return "unknown"
                return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except (TypeError, ValueError, OSError, OverflowError):
                return "unknown"

        def status_age(value: object) -> str:
            try:
                timestamp = int(value)
            except (TypeError, ValueError):
                return "unknown"
            if timestamp <= 0:
                return "unknown"
            delta = observed_now - timestamp
            if delta < 0:
                return f"future-dated by {-delta} seconds"
            if delta < 60:
                return f"{delta} seconds"
            if delta < 3600:
                return f"{delta // 60} minutes"
            if delta < 86400:
                return f"{delta // 3600} hours"
            return f"{delta // 86400} days"

        rows: list[str] = []
        for index, binding in enumerate(bindings, start=1):
            rows.append(
                f"{index}. {binding.get('callsign', 'unknown')} — key {binding.get('key_id_sha256', 'unknown')}"
            )
            rows.append(f"   Purposes: {', '.join(map(str, binding.get('purposes', [])))}")
            rows.append(f"   Certificate: {binding.get('certificate_sha256', 'unknown')}")
            rows.append(f"   Issuer: {binding.get('certificate_issuer', 'unknown')}")
            rows.append(f"   Expires: {instant(binding.get('certificate_expires_at'))}")
            rows.append(f"   Status: {binding.get('certificate_status', 'unknown')}")
            age = status_age(binding.get("status_observed_at"))
            age_label = f"({age})" if age.startswith("future-dated") or age == "unknown" else f"({age} old)"
            rows.append(f"   Status observed: {instant(binding.get('status_observed_at'))} {age_label}")
            rows.append(f"   Status source: {binding.get('status_source', 'unknown')}")
            rows.append(f"   Binding: {'disabled' if binding.get('disabled') else 'enabled'}")
        return "\n".join(rows)

    def refresh_enrollment(self) -> None:
        try:
            response = self.enrollment_refresh_response.get().strip()
            callsign = self.enrollment_refresh_call.get().strip()
            key_id = self.enrollment_refresh_key.get().strip()
            store = self.enrollment_path.get().strip()
            roots = self.enrollment_verify_roots.get().strip()
            age = self.enrollment_verify_status_age.get().strip()
            if not all((response, callsign, key_id, store, age)):
                raise ValueError("Choose the accepted response, callsign, key fingerprint, enrollment database, and maximum status age.")
            try:
                age_hours = int(age)
            except ValueError as exc:
                raise ValueError("Maximum status age must be a whole number of hours.") from exc
            if not 1 <= age_hours <= 720:
                raise ValueError("Maximum status age must be between 1 and 720 hours.")
            if not messagebox.askyesno(
                "Refresh LoTW certificate status",
                "This revalidates the stored certificate chain and contacts LoTW for current status. It does not change the callsign, key, purposes, or disabled state. Continue?",
                parent=self.root,
            ):
                return
            args = ["enrollment", "refresh", "--response", response,
                    "--callsign", callsign, "--key-id", key_id, "--store", store,
                    "--max-status-age", f"{age_hours}h"]
            if roots:
                args.extend(("--roots", roots))
            code, output = self.run_cli(args, (0, 1))
            detail = json.dumps(json.loads(output), indent=2)
            self._report("Certificate status refreshed" if code == 0 else "Certificate status not refreshed", detail)
        except Exception as exc: self._error(exc)

    def disable_enrollment(self) -> None:
        try:
            path = self.enrollment_path.get().strip()
            callsign = self.enrollment_disable_call.get().strip()
            key_id = self.enrollment_disable_key.get().strip()
            if not path or not callsign or not key_id: raise ValueError("Choose the enrollment database and enter a callsign and key fingerprint.")
            self.run_cli(["enrollment", "disable", "--store", path, "--callsign", callsign, "--key-id", key_id])
            self._report("Enrollment disabled", f"The enrollment binding for {callsign.upper()} was disabled.")
        except Exception as exc: self._error(exc)

    def issue_enrollment(self) -> None:
        try:
            audience = self.enrollment_audience.get().strip()
            callsign = self.enrollment_issue_call.get().strip()
            public_key = self.enrollment_issue_public.get().strip()
            output = self.enrollment_issue_out.get().strip()
            store = self.enrollment_path.get().strip()
            lifetime = self.enrollment_issue_lifetime.get().strip()
            if not all((audience, callsign, public_key, output, store, lifetime)):
                raise ValueError("Complete audience, callsign, public key, output, enrollment database and lifetime fields.")
            try:
                seconds = int(lifetime)
            except ValueError as exc:
                raise ValueError("Challenge lifetime must be a whole number of seconds.") from exc
            if not 1 <= seconds <= 300:
                raise ValueError("Challenge lifetime must be between 1 and 300 seconds.")
            _, result = self.run_cli([
                "enrollment", "issue", "--audience", audience, "--callsign", callsign,
                "--public-key", public_key, "--store", store, "--out", output,
                "--expires-in", str(seconds),
            ])
            self._report("Enrollment challenge issued", f"{result}\n\nThis has not been signed by TQSL and does not create a LoTW enrollment binding.")
        except Exception as exc: self._error(exc)

    def respond_enrollment(self) -> None:
        try:
            request = self.enrollment_respond_request.get().strip()
            key = self.enrollment_respond_key.get().strip()
            output = self.enrollment_respond_out.get().strip()
            helper = self.enrollment_tqsl_helper.get().strip()
            serial = self.enrollment_tqsl_serial.get().strip()
            if not all((request, key, output)):
                raise ValueError("Choose the challenge, ARAP private key and response output file.")
            if not self.enrollment_sign_allow_legacy.get():
                raise ValueError("Enable the RSA/SHA-1 policy checkbox to proceed. TQSL's raw challenge API uses this legacy algorithm.")
            confirmed = messagebox.askyesno(
                "Legacy TQSL enrollment signature",
                "This signs the fresh ARAP enrollment challenge with TQSL's legacy RSA/SHA-1 API and also signs it with the matching ARAP Ed25519 key. It does not create or upload a QSO. Continue?",
                parent=self.root,
            )
            if not confirmed:
                return
            arap_password = self._ask_passphrase("Unlock ARAP private key")
            tqsl_password = simpledialog.askstring(
                "Unlock TQSL certificate",
                "TQSL certificate password (leave blank if the certificate is not password protected):",
                show="•",
                parent=self.root,
            )
            if tqsl_password is None:
                raise ValueError("TQSL password entry cancelled.")
            if "\n" in arap_password or "\r" in arap_password or "\n" in tqsl_password or "\r" in tqsl_password:
                raise ValueError("Passphrases cannot contain a newline in this input mode.")
            args = [
                "enrollment", "respond", "--request", request,
                "--private-key", key, "--out", output,
                "--passphrase-stdin", "--allow-legacy-rsa-sha1",
            ]
            if helper:
                args.extend(("--tqsl-helper", helper))
            if serial:
                args.extend(("--tqsl-serial", serial))
            _, result = self.run_cli(args, input_text=f"{arap_password}\n{tqsl_password}\n")
            self._report("Enrollment response created", f"{result}\n\nSend this response to the verifier that issued the challenge. It contains a short-lived TQSL RSA/SHA-1 enrollment assertion; it is not an ARAP content signature or a QSO upload.")
        except Exception as exc: self._error(exc)

    def list_enrollment_certificates(self) -> None:
        try:
            request = self.enrollment_respond_request.get().strip()
            helper = self.enrollment_tqsl_helper.get().strip()
            if not request:
                raise ValueError("Choose the enrollment challenge file first.")
            args = ["enrollment", "certificates", "--request", request]
            if helper:
                args.extend(("--tqsl-helper", helper))
            _, output = self.run_cli(args)
            result = json.loads(output)
            certificates = result.get("certificates", [])
            if not certificates:
                self._report("Matching TQSL certificates", f"No current TQSL certificate was found for {result.get('callsign', 'the challenge callsign')}.")
                return
            serials = "\n".join(f"{item['callsign']} — serial {item['serial']}" for item in certificates)
            self._report("Matching TQSL certificates", f"Select the serial to use, then enter it in the certificate serial field.\n\n{serials}")
        except Exception as exc: self._error(exc)

    def verify_enrollment(self) -> None:
        try:
            response = self.enrollment_verify_response.get().strip()
            audience = self.enrollment_verify_audience.get().strip()
            roots = self.enrollment_verify_roots.get().strip()
            store = self.enrollment_path.get().strip()
            age = self.enrollment_verify_status_age.get().strip()
            if not all((response, audience, store, age)):
                raise ValueError("Choose the response, audience, enrollment database and maximum status age; roots are an optional override.")
            try:
                age_hours = int(age)
            except ValueError as exc:
                raise ValueError("Maximum status age must be a whole number of hours.") from exc
            if not 1 <= age_hours <= 720:
                raise ValueError("Maximum status age must be between 1 and 720 hours.")

            args = [
                "enrollment", "verify-response", "--response", response,
                "--audience", audience, "--roots", roots, "--store", store,
                "--max-status-age", f"{age_hours}h",
            ]
            if self.enrollment_allow_legacy_rsa_sha1.get():
                confirmed = messagebox.askyesno(
                    "Legacy TQSL signature policy",
                    "This verifies an enrollment assertion with TQSL's legacy RSA/SHA-1 signature and contacts LoTW for certificate status. Continue?",
                    parent=self.root,
                )
                if not confirmed:
                    return
                args.append("--allow-legacy-rsa-sha1")
            code, output = self.run_cli(args, (0, 1))
            detail = json.dumps(json.loads(output), indent=2)
            title = "Enrollment accepted" if code == 0 else "Enrollment not accepted"
            self._report(title, detail)
        except Exception as exc: self._error(exc)

    def _server_base(self) -> str:
        return self._server_bases()[0]

    def _server_bases(self) -> list[str]:
        return self._validate_resolver_list(self.server_url.get())

    def _validate_server_base(self, base: str) -> str:
        parsed = urllib.parse.urlsplit(base)
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Enter a valid keyserver base URL.")
        loopback = parsed.hostname.lower() == "localhost"
        try:
            loopback = loopback or ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            pass
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise ValueError("Use HTTPS for remote keyservers.")
        return base

    def publish_key(self) -> None:
        try:
            base = self._server_base()
            path = self.server_public.get().strip()
            if not path: raise ValueError("Choose a public key file.")
            env = os.environ.copy()
            env["ARAP_UPLOAD_TOKEN"] = self.server_token.get()
            _, output = self.run_cli(["publish-key", "--server", base, "--public-key", path], env=env)
            result = json.loads(output)
            self._report("Public key published", f"Fingerprint: {result['key_id_sha256']}\n\nThe server stores the public key as an untrusted candidate.")
        except Exception as exc: self._error(exc)

    def publish_proof(self) -> None:
        try:
            base = self._server_base()
            path = self.server_proof.get().strip()
            if not path: raise ValueError("Choose a proof file.")
            env = os.environ.copy()
            env["ARAP_UPLOAD_TOKEN"] = self.server_token.get()
            _, output = self.run_cli(["publish", "--server", base, "--proof", path], env=env)
            result = json.loads(output)
            self.reference.set(result["reference"])
            self._report("Proof published", f"SHA-256: {result['proof_sha256']}\nShort reference: {result['reference']}")
        except Exception as exc: self._error(exc)

    def fetch_key(self) -> None:
        try:
            bases = self._server_bases()
            fingerprint = self.fetch_fingerprint.get().strip().lower()
            if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint): raise ValueError("Enter a 64-character SHA-256 SPKI fingerprint.")
            output = self.fetch_output.get().strip()
            if not output: raise ValueError("Choose a key output path.")
            args = ["fetch-key"]
            for base in bases: args.extend(["--server", base])
            args.extend(["--fingerprint", fingerprint, "--out", output])
            _, result = self.run_cli(args)
            self._report("Key fetched", f"{result}\n\nThe key remains untrusted until you add a local trust binding.")
        except Exception as exc: self._error(exc)

    def fetch_proof(self) -> None:
        try:
            bases = self._server_bases()
            reference = self.fetch_proof_ref.get().strip().upper().replace(" ", "").replace("-", "")
            output = self.fetch_proof_output.get().strip()
            if not output: raise ValueError("Choose a proof output path.")
            args = ["resolve"]
            for base in bases: args.extend(["--server", base])
            args.extend(["--reference", reference, "--out", output])
            _, result = self.run_cli(args)
            self._report("Proof fetched", f"{result}\n\nThe proof remains unverified until checked against its content and trust policy.")
        except Exception as exc: self._error(exc)

    def issue_challenge(self) -> None:
        try:
            requester, responder = self.challenge_requester.get().strip(), self.challenge_responder.get().strip()
            store, output = self.challenge_store.get().strip(), self.challenge_request_out.get().strip()
            if not all((requester, responder, store, output)): raise ValueError("Complete requester, responder, database and request output fields.")
            _, result = self.run_cli(["challenge", "issue", "--requester", requester, "--responder", responder, "--store", store, "--out", output])
            self._report("Challenge issued", result)
        except Exception as exc: self._error(exc)

    def respond_challenge(self) -> None:
        try:
            request, call = self.challenge_in_request.get().strip(), self.challenge_signer.get().strip()
            key, output = self.challenge_private.get().strip(), self.challenge_response_out.get().strip()
            if not all((request, call, key, output)): raise ValueError("Complete request, responder callsign, private key and response output fields.")
            passphrase = self._ask_passphrase("Unlock signing key")
            _, result = self.run_cli(["challenge", "respond", "--request", request, "--callsign", call, "--key", key, "--out", output, "--passphrase-stdin"], input_text=passphrase + "\n")
            self._report("Challenge response signed", result)
        except Exception as exc: self._error(exc)

    def verify_challenge(self) -> None:
        try:
            request, response = self.challenge_verify_request.get().strip(), self.challenge_verify_response.get().strip()
            key, trust = self.challenge_public.get().strip(), self.challenge_trust.get().strip()
            enrollment = self.challenge_enrollment.get().strip()
            requester, store = self.challenge_expected_requester.get().strip(), self.challenge_store.get().strip()
            if not all((request, response, key, requester, store)) or not (trust or enrollment): raise ValueError("Complete request, response, responder key, requester, replay database and at least one trust or enrollment database.")
            args = ["challenge", "verify-response", "--request", request, "--response", response, "--public-key", key, "--requester", requester, "--store", store]
            if trust: args.extend(["--trust-store", trust])
            if enrollment: args.extend(["--enrollment-store", enrollment])
            _, result = self.run_cli(args, (0, 1))
            self._report("Challenge verification", result)
        except Exception as exc: self._error(exc)


def main() -> None:
    root = tk.Tk()
    ARAPDesktop(root)
    root.mainloop()


if __name__ == "__main__":
    main()
