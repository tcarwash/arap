#!/usr/bin/env python3
"""Exercise packaged Tk workflows and verify that the adjacent CLI is callable."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import socket
import sys
import tempfile
import subprocess
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

import tkinter as tk


def widget_texts(widget: tk.Misc) -> list[str]:
    texts: list[str] = []
    for child in widget.winfo_children():
        try:
            value = child.cget("text")
            if value:
                texts.append(str(value))
        except tk.TclError:
            pass
        texts.extend(widget_texts(child))
    return texts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, help="test an extracted-from-ZIP desktop bundle")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="arap-desktop-smoke-") as temp:
        if args.bundle:
            bundle_dir = Path(temp)
            with zipfile.ZipFile(args.bundle) as bundle:
                for entry in bundle.infolist():
                    target = Path(entry.filename)
                    if target.is_absolute() or ".." in target.parts:
                        raise SystemExit(f"unsafe bundle path: {entry.filename}")
                bundle.extractall(bundle_dir)
                for entry in bundle.infolist():
                    mode = entry.external_attr >> 16 & 0o777
                    if mode:
                        os.chmod(bundle_dir / entry.filename, mode)
            script = bundle_dir / "arap_desktop.py"
            expected_cli = bundle_dir / ("arap.exe" if os.name == "nt" else "arap")
            expected_server = bundle_dir / ("arap-keyserver.exe" if os.name == "nt" else "arap-keyserver")
        else:
            script = Path(__file__).resolve().parents[1] / "desktop" / "arap_desktop.py"
            expected_cli = script.parents[1] / "bin" / "arap"
            expected_server = script.parents[1] / "bin" / "arap-keyserver"

        spec = importlib.util.spec_from_file_location("arap_desktop_smoke", script)
        if spec is None or spec.loader is None:
            raise SystemExit(f"could not load desktop application: {script}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if args.bundle:
            helper_name = "arap-tqsl-sign.exe" if os.name == "nt" else "arap-tqsl-sign"
            expected_helper = bundle_dir / helper_name
            if expected_helper.is_file() and Path(module.find_tqsl_helper()).resolve() != expected_helper.resolve():
                raise SystemExit("desktop did not discover the adjacent native TQSL helper")
        root = tk.Tk()
        root.geometry("840x620")
        try:
            app = module.ARAPDesktop(root)
            if app.tabs.tab(app.tabs.tabs()[0], "text") != "Start here":
                raise SystemExit("workflow guide must be the first desktop tab")
            app.select_tab("Challenge")
            challenge_id = next(tab_id for tab_id in app.tabs.tabs()
                                if app.tabs.tab(tab_id, "text") == "Challenge")
            challenge_tab = root.nametowidget(challenge_id)
            challenge_text = " ".join(widget_texts(challenge_tab)).lower()
            if ("requester / verifier" not in challenge_text or "responder" not in challenge_text
                    or "mutual authentication" not in challenge_text):
                raise SystemExit("challenge workflow role guidance is missing")
            app.select_tab("Endorsements")
            endorsement_id = next(tab_id for tab_id in app.tabs.tabs()
                                  if app.tabs.tab(tab_id, "text") == "Endorsements")
            endorsement_text = " ".join(widget_texts(root.nametowidget(endorsement_id))).lower()
            if "explicit root" not in endorsement_text or "verify chain" not in endorsement_text:
                raise SystemExit("endorsement trust guidance or verification controls are missing")
            app.endorse_issuer.set("K7ABC")
            app.endorse_private.set("issuer.age")
            app.endorse_subject.set("AG7SU")
            app.endorse_subject_public.set("subject.pem")
            app.endorse_purposes.set("content-signature, challenge-response")
            app.endorse_depth.set("1")
            app.endorse_days.set("30")
            app.endorse_output.set("endorsement.cose")
            endorsement_calls: list[list[str]] = []
            original_run_cli = app.run_cli
            original_report = app._report
            original_ask_passphrase = app._ask_passphrase
            app.run_cli = lambda args, *rest, **kwargs: (endorsement_calls.append(args) or 0, "{}")
            app._report = lambda *_args, **_kwargs: None
            app._ask_passphrase = lambda *_args, **_kwargs: "test-only-passphrase"
            try:
                app.issue_endorsement()
            finally:
                app.run_cli = original_run_cli
                app._report = original_report
                app._ask_passphrase = original_ask_passphrase
            if (not endorsement_calls or endorsement_calls[0][:2] != ["endorsement", "issue"]
                    or endorsement_calls[0].count("--purpose") != 2
                    or "--passphrase-stdin" not in endorsement_calls[0]):
                raise SystemExit("desktop endorsement issue did not pass purpose and secret safely to the CLI")
            app.endorse_chain_links.set("root-link.cose, delegate-link.cose")
            app.endorse_chain_output.set("chain.cbor")
            assembly_calls: list[list[str]] = []
            app.run_cli = lambda args, *rest, **kwargs: (assembly_calls.append(args) or 0, "{}")
            app._report = lambda *_args, **_kwargs: None
            try:
                app.pack_endorsement_chain()
            finally:
                app.run_cli = original_run_cli
                app._report = original_report
            if (not assembly_calls or assembly_calls[0][:2] != ["endorsement", "pack"]
                    or assembly_calls[0].count("--link") != 2
                    or app.endorse_chain.get() != "chain.cbor"):
                raise SystemExit("desktop endorsement chain assembly did not preserve ordered links")
            app.endorse_chain.set("chain.cbor")
            app.endorse_root_call.set("K7ABC")
            app.endorse_root_public.set("root.pem")
            app.endorse_root_purposes.set("content-signature, key-endorsement")
            app.endorse_root_depth.set("2")
            app.endorse_expected_subject.set("AG7SU")
            app.endorse_expected_public.set("subject.pem")
            app.endorse_verify_purpose.set("content-signature")
            verification_calls: list[list[str]] = []
            app.run_cli = lambda args, *rest, **kwargs: (verification_calls.append(args) or 0,
                                                         json.dumps({"accepted": True, "subject": "AG7SU"}))
            try:
                app.verify_endorsement()
            finally:
                app.run_cli = original_run_cli
            if (not verification_calls or verification_calls[0][:2] != ["endorsement", "verify"]
                    or verification_calls[0].count("--root-purpose") != 2
                    or "--subject-public-key" not in verification_calls[0]):
                raise SystemExit("desktop endorsement verification did not pass explicit root and subject policy")
            app.select_tab("Start here")
            sample_binding = {
                "callsign": "N0CALL", "key_id_sha256": "a" * 64,
                "purposes": ["challenge-response"], "certificate_sha256": "b" * 64,
                "certificate_issuer": "Synthetic Issuer", "certificate_expires_at": 2000,
                "certificate_status": "good", "status_observed_at": 1000,
                "status_source": "synthetic-test", "disabled": True,
            }
            binding_text = app.format_enrollment_bindings([sample_binding], now=2000)
            if "Expires: 1970-01-01 00:33:20 UTC" not in binding_text or "16 minutes old" not in binding_text or "Binding: disabled" not in binding_text:
                raise SystemExit("enrollment status summary omitted expiry, status age, or disablement")

            app.enrollment_refresh_response.set("accepted-response.cbor")
            app.enrollment_refresh_call.set("N0CALL")
            app.enrollment_refresh_key.set("a" * 64)
            app.enrollment_path.set("enrollment.sqlite")
            custom_tqsl_directory = str(Path(temp) / "custom-tqsl-data")
            app.enrollment_tqsl_directory.set(custom_tqsl_directory)
            refresh_calls: list[list[str]] = []
            refresh_reports: list[tuple[str, str]] = []
            original_run_cli = app.run_cli
            original_report = app._report
            app.run_cli = lambda args, *rest, **kwargs: (refresh_calls.append(args) or 0,
                                                         json.dumps({"accepted": True, "status": "good"}))
            app._report = lambda title, message: refresh_reports.append((title, message))
            original_askyesno = module.messagebox.askyesno
            module.messagebox.askyesno = lambda *args, **kwargs: True
            try:
                app.refresh_enrollment()
            finally:
                module.messagebox.askyesno = original_askyesno
                app.run_cli = original_run_cli
                app._report = original_report
            if (not refresh_calls or refresh_calls[0][:2] != ["enrollment", "refresh"]
                    or "--tqsl-directory" not in refresh_calls[0]
                    or custom_tqsl_directory not in refresh_calls[0]
                    or not refresh_reports):
                raise SystemExit("desktop status refresh did not call the supported CLI operation")
            diagnostics = app.setup_diagnostics_text()
            if "Python:" not in diagnostics or "Tk:" not in diagnostics or "ARAP CLI:" not in diagnostics:
                raise SystemExit("setup diagnostics omitted Python, Tk, or CLI state")
            if args.bundle and "TQSL helper:" not in diagnostics:
                raise SystemExit("setup diagnostics omitted TQSL helper state")
            manifest_values: dict[str, str] = {}
            manifest_path = script.with_name("BUILD-MANIFEST.txt")
            if manifest_path.is_file():
                for line in manifest_path.read_text(encoding="utf-8").splitlines():
                    if ": " in line:
                        key, value = line.split(": ", 1)
                        manifest_values[key] = value
            for executable, expected_name in ((expected_cli, "arap"), (expected_server, "arap-keyserver")):
                version_result = subprocess.run([str(executable), "version", "--json"],
                                                capture_output=True, text=True, check=False, timeout=10)
                if version_result.returncode:
                    raise SystemExit(f"{expected_name} version command failed: {version_result.stderr.strip()}")
                info = json.loads(version_result.stdout)
                if info.get("name") != expected_name:
                    raise SystemExit(f"{expected_name} reported the wrong executable name")
                if manifest_values and (info.get("version") != manifest_values.get("ARAP version")
                                        or info.get("commit") != manifest_values.get("Git base commit")):
                    raise SystemExit(f"{expected_name} version metadata does not match the bundle manifest")
            about_result: list[tuple[str, str]] = []
            original_showinfo = module.messagebox.showinfo
            module.messagebox.showinfo = lambda title, message, **kwargs: about_result.append((title, message))
            try:
                app.show_about()
            finally:
                module.messagebox.showinfo = original_showinfo
            if len(about_result) != 1 or "Source commit:" not in about_result[0][1]:
                raise SystemExit("About view is missing build version metadata")
            if args.bundle:
                expected_version = manifest_values["ARAP version"]
                expected_commit = manifest_values["Git base commit"]
                if expected_version not in about_result[0][1] or expected_commit not in about_result[0][1]:
                    raise SystemExit("About view version metadata does not match the bundle manifest")
            purpose_values = tuple(app.trust_purpose_picker.cget("values"))
            if str(app.trust_purpose_picker.cget("state")) != "readonly" or purpose_values != (
                "content-signature",
                "challenge-response",
            ):
                raise SystemExit("trust purpose must be selected from the supported purposes")
            root.update_idletasks()
            for tab_id in app.tabs.tabs():
                app.tabs.select(tab_id)
                root.update_idletasks()
                if app.tabs.tab(tab_id, "text") in ("Keys & Trust", "PixelQSO cards", "Keyserver", "Challenge"):
                    canvas = app._scroll_canvases[tab_id]
                    region = canvas.bbox("all")
                    if not region or region[3] <= canvas.winfo_height():
                        raise SystemExit(f"long form is not scrollable at minimum window size: {app.tabs.tab(tab_id, 'text')}")
                    canvas.yview_moveto(1.0)
                    root.update_idletasks()
                    if canvas.yview()[1] < 0.999:
                        raise SystemExit(f"cannot scroll to the end of form: {app.tabs.tab(tab_id, 'text')}")
                    canvas.yview_moveto(0.0)
                    if app.tabs.tab(tab_id, "text") == "Keyserver":
                        canvas.event_generate("<Enter>")
                        root.update()
                        canvas.event_generate("<MouseWheel>", delta=-120)
                        root.update_idletasks()
                        if canvas.yview()[0] <= 0:
                            raise SystemExit("mouse wheel did not scroll the keyserver form")
                        before = canvas.yview()[0]
                        canvas.event_generate("<Button-5>")
                        root.update_idletasks()
                        if canvas.yview()[0] <= before:
                            raise SystemExit("Linux wheel-down event did not scroll the keyserver form")
                        canvas.event_generate("<Button-4>")
                        root.update_idletasks()
                        canvas.event_generate("<Leave>")
                        root.update()
            app.tabs.select(0)
            root.update_idletasks()
            responsive = []
            root.after(10, lambda: responsive.append(all(str(button.cget("state")) == "disabled" for button in app._action_buttons)))
            root.after(10, app._request_close)
            app._run_blocking(lambda: time.sleep(0.1), "Checking UI responsiveness…")
            if responsive != [True]:
                raise SystemExit("Tk event loop or action locking failed during background work")
            if not root.winfo_exists() or not app.status.get().startswith("Wait for the current action"):
                raise SystemExit("desktop did not defer window close while an action was running")
            tab_names = [app.tabs.tab(tab, "text") for tab in app.tabs.tabs()]
            if "PixelQSO cards" not in tab_names:
                raise SystemExit(f"PixelQSO card workflow is missing from desktop tabs: {tab_names!r}")
            if not hasattr(app, "pixelqso_sign_first") or not hasattr(app, "pixelqso_verify_first"):
                raise SystemExit("desktop PixelQSO frame-pair controls are missing")
            if hasattr(app, "key_call"):
                raise SystemExit("key generation must not imply that the key is bound to a callsign")
            app.key_private.set(str(Path(temp) / "station-private.pem"))
            app.key_public.set(str(Path(temp) / "station-public.pem"))
            reports = []
            app._report = lambda title, message: reports.append((title, message))

            def fail_on_ui_error(exc: Exception) -> None:
                raise RuntimeError(f"desktop action failed: {exc}") from exc

            app._error = fail_on_ui_error
            app._ask_passphrase = lambda _title, confirm=False: "desktop smoke passphrase"
            app.generate_keys()
            if not reports or "encrypted in the age file format" not in reports[-1][1] or "OS keychain" not in reports[-1][1]:
                raise SystemExit("desktop key-generation result did not explain private-key storage")
            private_key = Path(app.key_private.get())
            public_key = Path(app.key_public.get())
            if not private_key.is_file() or not public_key.is_file():
                raise SystemExit("desktop key-generation action did not create both key files")
            if os.name != "nt" and private_key.stat().st_mode & 0o077:
                raise SystemExit("desktop key-generation action did not protect the private key")
            cli = Path(app.cli.get()).resolve()
            if cli != expected_cli.resolve():
                raise SystemExit(f"desktop selected unexpected CLI path: {cli}")
            code, output = app.run_cli(["--help"])
            if code != 0 or "ARAP proof and identity tools" not in output:
                raise SystemExit(f"adjacent CLI smoke check failed: code={code}, output={output!r}")

            content = Path(temp) / "payload.bin"
            proof = Path(temp) / "payload.cose"
            trust = Path(temp) / "trust.json"
            content.write_bytes(b"ARAP desktop end-to-end smoke\n")
            app.sign_call.set("AG7SU")
            app.sign_key.set(str(private_key))
            app.sign_input.set(str(content))
            app.sign_media.set("application/octet-stream")
            app.sign_context.set("arap/desktop-smoke/v1")
            app.sign_output.set(str(proof))
            app.sign_content()
            if not proof.is_file():
                raise SystemExit("desktop signing action did not create a proof")

            app.trust_path.set(str(trust))
            app.trust_public.set(str(public_key))
            app.trust_call.set("AG7SU")
            app.trust_purpose.set("content-signature")
            app.add_trust()
            app.verify_proof.set(str(proof))
            app.verify_input.set(str(content))
            app.verify_public.set(str(public_key))
            app.verify_trust.set(str(trust))
            app.verify_media.set("application/octet-stream")
            app.verify_context.set("arap/desktop-smoke/v1")
            app.verify_call.set("AG7SU")
            app.verify_content()
            result = json.loads(app.result.get("1.0", "end"))
            if result.get("overall_policy") != "accepted":
                raise SystemExit(f"desktop verification rejected its signed content: {result!r}")

            vectors = Path(__file__).resolve().parents[1] / "test-vectors" / "pixelqso-card-v1"
            card = vectors / "card.json"
            first = vectors / "first-card.json"
            card_proof = Path(temp) / "frame-2.cose"
            app.pixelqso_sign_card.set(str(card))
            app.pixelqso_sign_key.set(str(private_key))
            app.pixelqso_sign_first.set(str(first))
            app.pixelqso_sign_proof.set(str(card_proof))
            app.sign_pixelqso()
            app.pixelqso_verify_card.set(str(card))
            app.pixelqso_verify_first.set(str(first))
            app.pixelqso_verify_proof.set(str(card_proof))
            app.pixelqso_verify_public.set(str(public_key))
            app.pixelqso_verify_trust.set(str(trust))
            app.verify_pixelqso()
            card_result = json.loads(app.pixelqso_result.get("1.0", "end"))
            if card_result.get("overall_policy") != "accepted":
                raise SystemExit(f"desktop frame-2 verification rejected its signed card: {card_result!r}")

            wrong_first = json.loads(first.read_text(encoding="utf-8"))
            wrong_first["pixels"][0] = (wrong_first["pixels"][0] + 1) % len(wrong_first["palette"])
            wrong_first_path = Path(temp) / "wrong-first-card.json"
            wrong_first_path.write_text(json.dumps(wrong_first), encoding="utf-8")
            app.pixelqso_verify_first.set(str(wrong_first_path))
            pair_errors = []
            app._error = lambda exc: pair_errors.append(str(exc))
            app.verify_pixelqso()
            if not any("first-card artwork fingerprint does not match" in error for error in pair_errors):
                raise SystemExit(f"desktop did not report a mismatched frame-1 card: {pair_errors!r}")
            app._error = fail_on_ui_error
            app.pixelqso_verify_first.set(str(first))

            app.trust_purpose.set("challenge-response")
            app.add_trust()
            request_path = Path(temp) / "challenge-request.cbor"
            response_path = Path(temp) / "challenge-response.cose"
            replay_db = Path(temp) / "challenge-replay.sqlite"
            app.challenge_requester.set("W1XYZ")
            app.challenge_responder.set("AG7SU")
            app.challenge_store.set(str(replay_db))
            app.challenge_request_out.set(str(request_path))
            app.issue_challenge()
            app.challenge_in_request.set(str(request_path))
            app.challenge_signer.set("AG7SU")
            app.challenge_private.set(str(private_key))
            app.challenge_response_out.set(str(response_path))
            app.respond_challenge()
            app.challenge_verify_request.set(str(request_path))
            app.challenge_verify_response.set(str(response_path))
            app.challenge_public.set(str(public_key))
            app.challenge_trust.set(str(trust))
            app.challenge_expected_requester.set("W1XYZ")
            app.verify_challenge()
            challenge_result = json.loads(reports[-1][1])
            if challenge_result.get("overall_policy") != "accepted":
                raise SystemExit(f"desktop challenge verification failed: {challenge_result!r}")
            app.verify_challenge()
            replay_result = json.loads(reports[-1][1])
            if replay_result.get("overall_policy") == "accepted":
                raise SystemExit("desktop challenge workflow accepted a replayed response")

            # Exercise the desktop's coordinated mutual flow with two distinct
            # identities, two response signatures, shared trust and one replay DB.
            private_a, public_a = private_key, public_key
            private_b = Path(temp) / "party-b-private.pem"
            public_b = Path(temp) / "party-b-public.pem"
            app.key_private.set(str(private_b))
            app.key_public.set(str(public_b))
            app.generate_keys()
            app.trust_path.set(str(trust))
            app.trust_public.set(str(public_b))
            app.trust_call.set("K7ABC")
            app.trust_purpose.set("challenge-response")
            app.add_trust()

            mutual_request_a = Path(temp) / "mutual-from-a.cbor"
            mutual_request_b = Path(temp) / "mutual-from-b.cbor"
            mutual_response_b = Path(temp) / "mutual-response-b.cose"
            mutual_response_a = Path(temp) / "mutual-response-a.cose"
            app.mutual_party_a.set("AG7SU")
            app.mutual_party_b.set("K7ABC")
            app.mutual_session_hex.set("617261702d736d6f6b652d73657373696f6e")
            app.mutual_out_from_a.set(str(mutual_request_a))
            app.mutual_out_from_b.set(str(mutual_request_b))
            app.issue_mutual_challenges()
            app.challenge_in_request.set(str(mutual_request_a))
            app.challenge_signer.set("K7ABC")
            app.challenge_private.set(str(private_b))
            app.challenge_response_out.set(str(mutual_response_b))
            app.respond_challenge()
            app.challenge_in_request.set(str(mutual_request_b))
            app.challenge_signer.set("AG7SU")
            app.challenge_private.set(str(private_a))
            app.challenge_response_out.set(str(mutual_response_a))
            app.respond_challenge()
            app.mutual_request_from_a.set(str(mutual_request_a))
            app.mutual_response_from_b.set(str(mutual_response_b))
            app.mutual_request_from_b.set(str(mutual_request_b))
            app.mutual_response_from_a.set(str(mutual_response_a))
            app.mutual_public_a.set(str(public_a))
            app.mutual_public_b.set(str(public_b))
            app.mutual_trust_a.set(str(trust))
            app.mutual_trust_b.set(str(trust))
            app.verify_mutual_challenges()
            mutual_result = json.loads(reports[-1][1])
            if not mutual_result.get("accepted"):
                raise SystemExit(f"desktop mutual challenge verification failed: {mutual_result!r}")
            app.verify_mutual_challenges()
            mutual_replay = json.loads(reports[-1][1])
            if mutual_replay.get("accepted"):
                raise SystemExit("desktop mutual challenge workflow accepted a replayed pair")
            # Restore the single-party values used by the following content
            # reference and trust-disable/reenable smoke checks.
            app.trust_public.set(str(public_a))
            app.trust_call.set("AG7SU")

            if not expected_server.is_file():
                raise SystemExit(f"adjacent keyserver executable is missing: {expected_server}")
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            server_env = os.environ.copy()
            server_env.update({
                "ARAP_DATA_DIR": str(Path(temp) / "keyserver-data"),
                "ARAP_UPLOAD_TOKEN": "desktop-smoke-upload-token-0123456789abcdef",
                "ARAP_LISTEN": f"127.0.0.1:{port}",
            })
            with open(os.devnull, "wb") as sink:
                server = subprocess.Popen([str(expected_server)], env=server_env, stdout=sink, stderr=sink)
                try:
                    base = f"http://127.0.0.1:{port}"
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        if server.poll() is not None:
                            raise SystemExit("keyserver exited before becoming healthy")
                        try:
                            with urllib.request.urlopen(base + "/healthz", timeout=0.5) as response:
                                if response.status == 200:
                                    break
                        except Exception:
                            time.sleep(0.05)
                    else:
                        raise SystemExit("keyserver did not become healthy")

                    app.server_url.set(base)
                    app.server_token.set("desktop-smoke-upload-token-0123456789abcdef")
                    app.server_public.set(str(public_key))
                    app.publish_key()
                    fetched_key = Path(temp) / "fetched-public.pem"
                    app.fetch_fingerprint.set(app.run_cli(["fingerprint", "--public-key", str(public_key)])[1].strip())
                    app.fetch_output.set(str(fetched_key))
                    app.fetch_key()
                    if fetched_key.read_bytes() != public_key.read_bytes():
                        raise SystemExit("desktop keyserver workflow returned different public-key bytes")

                    app.server_proof.set(str(proof))
                    app.publish_proof()
                    fetched_proof = Path(temp) / "fetched-proof.cose"
                    app.fetch_proof_ref.set(app.reference.get())
                    app.fetch_proof_output.set(str(fetched_proof))
                    app.fetch_proof()
                    if fetched_proof.read_bytes() != proof.read_bytes():
                        raise SystemExit("desktop keyserver workflow returned different proof bytes")

                    app.ref_server_url.set(base)
                    app.ref_reference.set(app.reference.get())
                    app.ref_content.set(str(content))
                    app.ref_public.set(str(public_key))
                    app.ref_trust.set(str(trust))
                    app.ref_media.set("application/octet-stream")
                    app.ref_context.set("arap/desktop-smoke/v1")
                    app.ref_call.set("AG7SU")
                    app.verify_reference()
                    reference_result = json.loads(app.ref_result.get("1.0", "end"))
                    if reference_result.get("overall_policy") != "accepted":
                        raise SystemExit(f"desktop reference verification rejected trusted content: {reference_result!r}")

                    content.write_bytes(b"edited content must fail reference verification")
                    app.verify_reference()
                    edited_reference_result = json.loads(app.ref_result.get("1.0", "end"))
                    if edited_reference_result.get("overall_policy") == "accepted":
                        raise SystemExit("desktop reference verification accepted content that differs from the published proof")
                    content.write_bytes(b"ARAP desktop end-to-end smoke\n")

                    app.trust_disable_call.set("AG7SU")
                    app.trust_disable_key.set(app.run_cli(["fingerprint", "--public-key", str(public_key)])[1].strip())
                    app.disable_trust()
                    app.verify_reference()
                    disabled_reference_result = json.loads(app.ref_result.get("1.0", "end"))
                    if disabled_reference_result.get("overall_policy") == "accepted":
                        raise SystemExit("desktop accepted a reference after disabling its trust binding")
                    app.trust_purpose.set("content-signature")
                    app.add_trust()
                    app.verify_reference()
                    reenabled_reference_result = json.loads(app.ref_result.get("1.0", "end"))
                    if reenabled_reference_result.get("overall_policy") != "accepted":
                        raise SystemExit(f"desktop could not re-enable the selected trust purpose: {reenabled_reference_result!r}")
                    _, stored_trust = app.run_cli(["trust", "list", "--store", str(trust)])
                    binding = next(item for item in json.loads(stored_trust)["bindings"] if item["callsign"] == "AG7SU")
                    if binding["purposes"] != ["content-signature"]:
                        raise SystemExit(f"desktop re-enabled unselected trust purposes: {binding['purposes']!r}")
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=5)
        finally:
            for worker in threading.enumerate():
                if worker.name == "arap-desktop-action":
                    worker.join(timeout=5)
            for name, value in list(vars(app).items()):
                if isinstance(value, tk.Variable):
                    setattr(app, name, None)
            root.update_idletasks()
            root.destroy()
        print("Tk desktop exercised content and PixelQSO proofs, one-way and mutual challenge authentication including replay rejection, endorsement issue/chain assembly/explicit-root verification, and keyserver publication, resolution, trust disable/re-enable and content edits.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
