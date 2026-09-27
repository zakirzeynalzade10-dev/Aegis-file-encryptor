"""
AEGIS CRYPT - Desktop GUI
==========================
Pure tkinter (standard library only — no extra GUI dependency), so it runs
on any machine with a normal Python 3 install with zero compatibility risk.
Dark, high-contrast, tactical/HUD-inspired styling.
"""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import aegis_core as core

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
BG_DARKEST = "#0a0d0a"
BG_PANEL = "#10140f"
BG_FIELD = "#161b15"
FG_PRIMARY = "#c8f5d4"
FG_DIM = "#5f7a63"
ACCENT = "#39ff88"      # tactical phosphor green
ACCENT_DIM = "#1f8a4c"
WARN = "#ffb020"
DANGER = "#ff4d4f"
BORDER = "#233026"
FONT_MONO = ("Consolas", 10)
FONT_MONO_BOLD = ("Consolas", 10, "bold")
FONT_TITLE = ("Consolas", 20, "bold")
FONT_LABEL = ("Consolas", 9)


class HudFrame(tk.Frame):
    """A panel with drawn corner brackets for a HUD/tactical look."""

    def __init__(self, master, **kw):
        super().__init__(master, bg=BG_PANEL, highlightthickness=1,
                          highlightbackground=BORDER, **kw)
        self._canvas = tk.Canvas(self, bg=BG_PANEL, highlightthickness=0)
        self._canvas.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.bind("<Configure>", self._redraw)

    def _redraw(self, _event=None):
        c = self._canvas
        c.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        s = 14
        for x, y, dx, dy in ((0, 0, 1, 1), (w, 0, -1, 1), (0, h, 1, -1), (w, h, -1, -1)):
            c.create_line(x, y, x + dx * s, y, fill=ACCENT_DIM, width=2)
            c.create_line(x, y, x, y + dy * s, fill=ACCENT_DIM, width=2)


class AegisApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AEGIS CRYPT // AES-256 FILE ENCRYPTION SYSTEM")
        self.geometry("760x560")
        self.minsize(680, 500)
        self.configure(bg=BG_DARKEST)

        self._selected_path: str | None = None
        self._worker_queue: "queue.Queue" = queue.Queue()
        self._busy = False

        self._build_style()
        self._build_layout()
        self.after(80, self._poll_queue)

    # ------------------------------------------------------------------
    # Styling
    # ------------------------------------------------------------------
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Aegis.Horizontal.TProgressbar",
                         troughcolor=BG_FIELD, background=ACCENT,
                         bordercolor=BORDER, lightcolor=ACCENT, darkcolor=ACCENT)
        style.configure("TRadiobutton", background=BG_PANEL, foreground=FG_PRIMARY,
                         font=FONT_MONO)
        style.map("TRadiobutton",
                   background=[("active", BG_PANEL)],
                   foreground=[("active", ACCENT)])

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build_layout(self):
        header = tk.Frame(self, bg=BG_DARKEST)
        header.pack(fill="x", padx=18, pady=(16, 8))

        tk.Label(header, text="AEGIS", font=FONT_TITLE, fg=ACCENT, bg=BG_DARKEST).pack(side="left")
        tk.Label(header, text=" CRYPT", font=FONT_TITLE, fg=FG_PRIMARY, bg=BG_DARKEST).pack(side="left")
        tk.Label(header, text="  AES-256-GCM // SCRYPT KDF // AUTHENTICATED STORAGE",
                 font=FONT_LABEL, fg=FG_DIM, bg=BG_DARKEST).pack(side="left", padx=(14, 0), pady=(8, 0))

        sep = tk.Frame(self, bg=ACCENT_DIM, height=2)
        sep.pack(fill="x", padx=18)

        body = HudFrame(self)
        body.pack(fill="both", expand=True, padx=18, pady=14)
        inner = tk.Frame(body, bg=BG_PANEL)
        inner.pack(fill="both", expand=True, padx=22, pady=20)

        # File selection
        tk.Label(inner, text="TARGET FILE", font=FONT_MONO_BOLD, fg=ACCENT, bg=BG_PANEL).grid(
            row=0, column=0, sticky="w")
        self._path_var = tk.StringVar(value="[ no file selected ]")
        path_row = tk.Frame(inner, bg=BG_FIELD, highlightthickness=1, highlightbackground=BORDER)
        path_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 14))
        tk.Label(path_row, textvariable=self._path_var, font=FONT_MONO, fg=FG_PRIMARY,
                 bg=BG_FIELD, anchor="w").pack(side="left", fill="x", expand=True, padx=10, pady=8)
        tk.Button(path_row, text="BROWSE", command=self._browse, font=FONT_MONO_BOLD,
                  bg=BG_FIELD, fg=ACCENT, activebackground=BG_FIELD, activeforeground=ACCENT,
                  relief="flat", highlightthickness=1, highlightbackground=ACCENT_DIM,
                  padx=14).pack(side="right", padx=8, pady=6)

        # Mode
        tk.Label(inner, text="OPERATION", font=FONT_MONO_BOLD, fg=ACCENT, bg=BG_PANEL).grid(
            row=2, column=0, sticky="w")
        mode_row = tk.Frame(inner, bg=BG_PANEL)
        mode_row.grid(row=3, column=0, columnspan=2, sticky="w", pady=(4, 14))
        self._mode_var = tk.StringVar(value="encrypt")
        ttk.Radiobutton(mode_row, text="ENCRYPT", value="encrypt", variable=self._mode_var,
                        style="TRadiobutton").pack(side="left", padx=(0, 24))
        ttk.Radiobutton(mode_row, text="DECRYPT", value="decrypt", variable=self._mode_var,
                        style="TRadiobutton").pack(side="left")

        # Password
        tk.Label(inner, text="PASSPHRASE", font=FONT_MONO_BOLD, fg=ACCENT, bg=BG_PANEL).grid(
            row=4, column=0, sticky="w")
        pw_row = tk.Frame(inner, bg=BG_FIELD, highlightthickness=1, highlightbackground=BORDER)
        pw_row.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(4, 4))
        self._pw_var = tk.StringVar()
        self._pw_entry = tk.Entry(pw_row, textvariable=self._pw_var, show="*", font=FONT_MONO,
                                   bg=BG_FIELD, fg=FG_PRIMARY, insertbackground=ACCENT,
                                   relief="flat")
        self._pw_entry.pack(side="left", fill="x", expand=True, padx=10, pady=8)
        self._show_pw = tk.BooleanVar(value=False)
        tk.Checkbutton(pw_row, text="show", variable=self._show_pw, command=self._toggle_pw,
                       font=FONT_LABEL, fg=FG_DIM, bg=BG_FIELD, selectcolor=BG_FIELD,
                       activebackground=BG_FIELD, activeforeground=ACCENT).pack(side="right", padx=8)

        tk.Label(inner, text="CONFIRM PASSPHRASE (encrypt only)", font=FONT_LABEL, fg=FG_DIM,
                 bg=BG_PANEL).grid(row=6, column=0, sticky="w", pady=(10, 0))
        pw2_row = tk.Frame(inner, bg=BG_FIELD, highlightthickness=1, highlightbackground=BORDER)
        pw2_row.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(4, 16))
        self._pw2_var = tk.StringVar()
        self._pw2_entry = tk.Entry(pw2_row, textvariable=self._pw2_var, show="*", font=FONT_MONO,
                                    bg=BG_FIELD, fg=FG_PRIMARY, insertbackground=ACCENT,
                                    relief="flat")
        self._pw2_entry.pack(side="left", fill="x", expand=True, padx=10, pady=8)

        inner.grid_columnconfigure(0, weight=1)

        # Execute button
        self._exec_btn = tk.Button(inner, text="▶  EXECUTE", command=self._on_execute,
                                    font=("Consolas", 12, "bold"), bg=ACCENT, fg=BG_DARKEST,
                                    activebackground=ACCENT, activeforeground=BG_DARKEST,
                                    relief="flat", pady=10)
        self._exec_btn.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(0, 14))

        # Progress
        self._progress = ttk.Progressbar(inner, style="Aegis.Horizontal.TProgressbar",
                                          maximum=100)
        self._progress.grid(row=9, column=0, columnspan=2, sticky="ew")

        # Status / log
        self._status_var = tk.StringVar(value="STANDBY // AWAITING INPUT")
        tk.Label(inner, textvariable=self._status_var, font=FONT_MONO, fg=FG_DIM,
                 bg=BG_PANEL, anchor="w").grid(row=10, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        footer = tk.Frame(self, bg=BG_DARKEST)
        footer.pack(fill="x", padx=18, pady=(0, 14))
        tk.Label(footer, text="AEGIS CRYPT v1.0  |  Container format: .axc  |  "
                              "Local-only. No network transmission.",
                 font=FONT_LABEL, fg=FG_DIM, bg=BG_DARKEST).pack(side="left")

    # ------------------------------------------------------------------
    # Interaction
    # ------------------------------------------------------------------
    def _toggle_pw(self):
        show = "" if self._show_pw.get() else "*"
        self._pw_entry.config(show=show)
        self._pw2_entry.config(show=show)

    def _browse(self):
        path = filedialog.askopenfilename(title="Select file")
        if path:
            self._selected_path = path
            display = path if len(path) < 70 else "..." + path[-67:]
            self._path_var.set(display)
            if path.lower().endswith(".axc"):
                self._mode_var.set("decrypt")

    def _set_busy(self, busy: bool):
        self._busy = busy
        state = "disabled" if busy else "normal"
        self._exec_btn.config(state=state, text="WORKING..." if busy else "▶  EXECUTE")

    def _on_execute(self):
        if self._busy:
            return
        path = self._selected_path
        if not path or not os.path.exists(path):
            messagebox.showerror("AEGIS CRYPT", "Select a valid file first.")
            return
        password = self._pw_var.get()
        mode = self._mode_var.get()

        if not password:
            messagebox.showerror("AEGIS CRYPT", "Passphrase cannot be empty.")
            return
        if mode == "encrypt":
            if password != self._pw2_var.get():
                messagebox.showerror("AEGIS CRYPT", "Passphrases do not match.")
                return
            if len(password) < 8:
                if not messagebox.askyesno("AEGIS CRYPT",
                                            "This passphrase is short and may be weak.\n"
                                            "Continue anyway?"):
                    return
            dst = path + ".axc"
        else:
            if not core.is_aegis_container(path):
                messagebox.showerror("AEGIS CRYPT", "Selected file is not an AEGIS container.")
                return
            dst = path[:-4] if path.lower().endswith(".axc") else path + ".decrypted"

        if os.path.exists(dst):
            if not messagebox.askyesno("AEGIS CRYPT", f"Output already exists:\n{dst}\n\nOverwrite?"):
                return

        self._set_busy(True)
        self._progress["value"] = 0
        self._status_var.set(f"PROCESSING // {os.path.basename(path)}")

        thread = threading.Thread(target=self._worker, args=(mode, path, dst, password), daemon=True)
        thread.start()

    def _worker(self, mode, src, dst, password):
        def progress_cb(p: core.Progress):
            self._worker_queue.put(("progress", p.fraction * 100))

        try:
            if mode == "encrypt":
                core.encrypt_file(src, dst, password, progress_cb=progress_cb, overwrite=True)
            else:
                core.decrypt_file(src, dst, password, progress_cb=progress_cb, overwrite=True)
            self._worker_queue.put(("done", dst))
        except core.InvalidPassword:
            self._worker_queue.put(("error", "Wrong passphrase, or the file is corrupted/tampered with."))
        except core.AegisError as e:
            self._worker_queue.put(("error", str(e)))
        except Exception as e:  # noqa: BLE001 - surface anything unexpected to the user
            self._worker_queue.put(("error", f"Unexpected error: {e}"))

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self._worker_queue.get_nowait()
                if kind == "progress":
                    self._progress["value"] = payload
                elif kind == "done":
                    self._set_busy(False)
                    self._status_var.set(f"COMPLETE // {payload}")
                    messagebox.showinfo("AEGIS CRYPT", f"Operation complete:\n{payload}")
                elif kind == "error":
                    self._set_busy(False)
                    self._progress["value"] = 0
                    self._status_var.set("ERROR // SEE DIALOG")
                    messagebox.showerror("AEGIS CRYPT", payload)
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)


def main():
    app = AegisApp()
    app.mainloop()


if __name__ == "__main__":
    main()
