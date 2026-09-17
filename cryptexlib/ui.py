"""The Cryptex window.

Nothing in here knows what any individual tool does. Every panel is built from
the Tool declaration in the registry, so a new tool appears in the interface
the moment it is registered.
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import traceback
import webbrowser

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import theme
from .core import (CATEGORY_ORDER, REGISTRY, Param, Result, Tool, ToolError,
                   app_dir, as_result, by_category, default_save_dir, downloads_dir,
                   search, settings_path)

APP = "Cryptex"
VERSION = "1.3"
SETTINGS = settings_path()

CATEGORY_BLURB = {
    "Identify": "Start here. Paste anything and find out what it is.",
    "Encodings": "Same information, different alphabet. Reversible by anyone — this is not secrecy.",
    "Classical ciphers": "Historical ciphers, all breakable, several with solvers built in.",
    "Encryption": "Real encryption. Authenticated, password-derived, safe to rely on.",
    "Hashing": "One-way fingerprints. No decrypt button exists, here or anywhere.",
    "Keys & certificates": "Two keys instead of one password: signatures, certificates, key exchange.",
    "Signals": "Sound that carries a picture or a message. Slow-scan television, touch-tones, Morse.",
    "Analysis": "Measure it before you guess: frequencies, entropy, repeats, raw bytes.",
    "Steganography": "Hidden, not encrypted: messages in pictures and text, and how to find them.",
    "Tokens & secrets": "One-time codes, web tokens, split secrets and checksum manifests.",
}


# --------------------------------------------------------------------------

class Tip:
    """A small hover tooltip."""

    def __init__(self, widget, text, colours):
        self.w, self.text, self.c, self.tip = widget, text, colours, None
        widget.bind("<Enter>", self.show, add="+")
        widget.bind("<Leave>", self.hide, add="+")

    def show(self, _=None):
        if self.tip or not self.text:
            return
        x = self.w.winfo_rootx() + 12
        y = self.w.winfo_rooty() + self.w.winfo_height() + 4
        self.tip = tk.Toplevel(self.w)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tip, text=self.text, justify="left", wraplength=340,
                 background=self.c["panel"], foreground=self.c["text"],
                 relief="solid", borderwidth=1, padx=8, pady=5).pack()

    def hide(self, _=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class App(ttk.Frame):
    def __init__(self, root):
        super().__init__(root)
        self.root = root
        self.settings = self._load_settings()
        self.dark = bool(self.settings.get("dark", True))   # dark by default
        self.c = theme.apply(root, self.dark)
        self.mono = theme.mono_family(root)
        self.ui = theme.ui_family(root)
        self.tool: Tool | None = None
        self.param_vars: dict[str, tk.Variable] = {}
        self.last_result: Result | None = None
        self.photo = None
        self.explain_open = tk.BooleanVar(value=bool(self.settings.get("explain_open", True)))
        self.busy = False
        self.streaming = False
        self.stop_event = None
        self.start_btn = None
        self.stop_btn = None
        self._selecting = False
        self.q: queue.Queue = queue.Queue()
        self.menus = []
        self.guide_win = None
        self.guide_txt = None
        self._wheel_rem = ("", 0.0)     # (widget path, fractional scroll carried over)

        root.title(f"{APP} — encoder / decoder toolbox")
        root.geometry(self.settings.get("geometry") or self._default_geometry(root))
        root.minsize(920, 600)
        self.pack(fill="both", expand=True)
        self._build_menu()
        self._build()
        self._bind_wheel()
        self._populate()
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(80, self._pump)
        first = self.settings.get("last_tool", "identify")
        self.select_tool(first if first in REGISTRY else "identify")

    # ---------------------------------------------------------------- setup

    @staticmethod
    def _default_geometry(root):
        """Open large, but never taller or wider than the screen it is on."""
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        w = min(1280, max(920, sw - 120))
        h = min(880, max(600, sh - 140))
        return f"{w}x{h}+{max(0,(sw-w)//2)}+{max(0,(sh-h)//3)}"

    def _load_settings(self):
        try:
            with open(SETTINGS, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}

    def _save_settings(self):
        try:
            try:
                self.settings["sash"] = self.pane.sashpos(0)
            except Exception:
                pass
            self.settings.update(dark=self.dark, geometry=self.root.geometry(),
                                 last_tool=self.tool.id if self.tool else "identify",
                                 explain_open=bool(self.explain_open.get()))
            with open(SETTINGS, "w", encoding="utf-8") as fh:
                json.dump(self.settings, fh, indent=1)
        except Exception:
            pass

    def _on_close(self):
        if self.streaming:
            self.stop_stream()
        self._save_settings()
        self.root.destroy()

    def _build_menu(self):
        m = tk.Menu(self.root)
        f = tk.Menu(m, tearoff=0)
        f.add_command(label="Open a file as input…", accelerator="Ctrl+O", command=self.open_file)
        f.add_command(label="Save output…", accelerator="Ctrl+S", command=self.save_output)
        f.add_separator()
        f.add_command(label="Default save folder…", command=self.choose_save_dir)
        f.add_command(label="Reset save folder to Downloads", command=self.reset_save_dir)
        f.add_separator()
        f.add_command(label="Quit", accelerator="Ctrl+Q", command=self._on_close)
        m.add_cascade(label="File", menu=f)
        e = tk.Menu(m, tearoff=0)
        e.add_command(label="Copy output", accelerator="Ctrl+Shift+C", command=self.copy_output)
        e.add_command(label="Paste into input", accelerator="Ctrl+V",
                      command=lambda: self.input_text.event_generate("<<Paste>>"))
        e.add_command(label="Send output to the input box", accelerator="Ctrl+Return", command=self.chain)
        e.add_command(label="Auto-solve this input", accelerator="Ctrl+Shift+S",
                      command=self._take_solve)
        e.add_command(label="Clear", command=self.clear)
        m.add_cascade(label="Edit", menu=e)
        v = tk.Menu(m, tearoff=0)
        v.add_command(label="Switch light / dark", accelerator="Ctrl+D", command=self.toggle_theme)
        v.add_checkbutton(label="Show the explanation panel", variable=self.explain_open,
                          command=self._render_explain)
        v.add_command(label="Find a tool", accelerator="Ctrl+F",
                      command=lambda: self.search_entry.focus_set())
        m.add_cascade(label="View", menu=v)
        h = tk.Menu(m, tearoff=0)
        h.add_command(label="What can this do?", command=self.show_guide)
        h.add_command(label="About Cryptex", command=self.show_about)
        m.add_cascade(label="Help", menu=h)
        self.menus = [m, f, e, v, h]
        self.root.config(menu=m)
        self.root.bind("<Control-o>", lambda e: self.open_file())
        self.root.bind("<Control-s>", lambda e: self.save_output())
        self.root.bind("<Control-q>", lambda e: self._on_close())
        self.root.bind("<Control-f>", lambda e: self.search_entry.focus_set())
        self.root.bind("<Control-d>", lambda e: self.toggle_theme())
        self.root.bind("<Control-Return>", lambda e: self.chain())
        self.root.bind("<Control-C>", lambda e: self.copy_output())
        self.root.bind("<F5>", lambda e: self.run_primary())
        self.root.bind("<Control-Shift-S>", lambda e: self._take_solve())

    def _build(self):
        c = self.c
        top = ttk.Frame(self, padding=(12, 10, 12, 6))
        top.pack(fill="x")
        ttk.Label(top, text="Cryptex", style="Title.TLabel").pack(side="left")
        ttk.Label(top, text="  encoder / decoder toolbox", style="Sub.TLabel").pack(side="left")
        self.theme_btn = ttk.Button(top, text="Dark" if not self.dark else "Light",
                                    width=7, command=self.toggle_theme)
        self.theme_btn.pack(side="right")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._populate())
        self.search_entry = ttk.Entry(top, textvariable=self.search_var, width=30)
        self.search_entry.pack(side="right", padx=(0, 10))
        ttk.Label(top, text="Search", style="Dim.TLabel").pack(side="right", padx=(0, 6))

        pane = ttk.PanedWindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=12, pady=(0, 4))

        side = ttk.Frame(pane, style="Side.TFrame")
        self.tree = ttk.Treeview(side, show="tree", selectmode="browse", style="Side.Treeview")
        self.tree.column("#0", width=270, minwidth=200, stretch=True)
        sb = ttk.Scrollbar(side, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        pane.add(side, weight=0)

        main = ttk.Frame(pane)
        pane.add(main, weight=1)
        try:
            pane.sashpos(0, int(self.settings.get("sash", 292)))
        except Exception:
            pass
        self.pane = pane

        head = ttk.Frame(main, padding=(14, 10, 6, 0))
        head.pack(fill="x")
        self.name_lbl = ttk.Label(head, text="", style="Title.TLabel")
        self.name_lbl.pack(anchor="w")
        self.sum_lbl = ttk.Label(head, text="", style="Sub.TLabel", wraplength=780)
        self.sum_lbl.pack(anchor="w", pady=(1, 0))

        self.explain_btn = ttk.Button(main, text="", width=30, command=self._toggle_explain)
        self.explain_btn.pack(anchor="w", padx=14, pady=(8, 0))
        self.explain_frame = ttk.Frame(main, style="Panel.TFrame", padding=1)
        self.explain = tk.Text(self.explain_frame, height=7, wrap="word", relief="flat",
                               padx=14, pady=11, borderwidth=0)
        self.explain.pack(fill="both", expand=True)
        self.explain.configure(state="disabled")

        self.warn_lbl = ttk.Label(main, text="", style="Warn.TLabel", wraplength=800)

        self.params_frame = ttk.Frame(main, padding=(14, 8, 14, 2))
        self.params_frame.pack(fill="x")
        self.params_inner = None
        self.param_holders = {}

        io = self.io = ttk.PanedWindow(main, orient="vertical")
        io.pack(fill="both", expand=True, padx=14, pady=(4, 0))

        inp = ttk.Frame(io)
        io.add(inp, weight=2)
        self.input_head = ttk.Label(inp, text="Input", style="Dim.TLabel")
        self.input_head.pack(anchor="w")
        self.file_row = ttk.Frame(inp)
        self.file_var = tk.StringVar()
        self.file_var.trace_add("write", lambda *a: self._schedule_file_info())
        self.file_entry = ttk.Entry(self.file_row, textvariable=self.file_var)
        self.file_entry.pack(side="left", fill="x", expand=True)
        self.file_btn = ttk.Button(self.file_row, text="Browse…", command=self.open_file)
        self.file_btn.pack(side="left", padx=(6, 0))
        self.text_wrap = ttk.Frame(inp, style="Panel.TFrame", padding=1)
        self.input_text = tk.Text(self.text_wrap, height=7, wrap="word", relief="flat",
                                  undo=True, padx=10, pady=8, borderwidth=0)
        isb = ttk.Scrollbar(self.text_wrap, orient="vertical", command=self.input_text.yview)
        self.input_text.configure(yscrollcommand=isb.set)
        self.input_text.pack(side="left", fill="both", expand=True)
        isb.pack(side="right", fill="y")
        for seq in ("<KeyRelease>", "<<Paste>>", "<<Cut>>", "<FocusIn>"):
            self.input_text.bind(seq, self._schedule_hint, add="+")
        self.text_wrap.pack(fill="both", expand=True, pady=(3, 0))

        # Detection bar: watches what you paste and says what it looks like,
        # with one click to jump to the tool that handles it.
        self.hint_bar = ttk.Frame(inp, style="Hint.TFrame")
        self.hint_lbl = ttk.Label(self.hint_bar, style="Hint.TLabel", wraplength=760)
        self.hint_lbl.pack(side="left", fill="x", expand=True)
        self.solve_btn = ttk.Button(self.hint_bar, text="Auto-solve", style="Hint.TButton",
                                    command=self._take_solve)
        self.hint_btn = ttk.Button(self.hint_bar, text="", style="Hint.TButton",
                                   command=self._take_hint)
        self.hint_suggest = None
        self.hint_job = None
        self.file_info = ttk.Label(inp, text="", style="Dim.TLabel", wraplength=760)

        btns = self.btns = ttk.Frame(main, padding=(14, 8, 14, 4))
        # side="bottom" with before=io: the button row claims the bottom of the
        # cavity BEFORE the expanding input/output area takes the rest, so it
        # can never be squeezed off the bottom of a short window.
        btns.pack(side="bottom", fill="x", before=io)
        self.dir_btns = ttk.Frame(btns)
        self.dir_btns.pack(side="left")
        ttk.Button(btns, text="Clear", command=self.clear).pack(side="right")
        ttk.Button(btns, text="Save output…", command=self.save_output).pack(side="right", padx=6)
        ttk.Button(btns, text="Copy", command=self.copy_output).pack(side="right")
        self.chain_btn = ttk.Button(btns, text="Send output to the input box", command=self.chain)
        self.chain_btn.pack(side="right", padx=6)

        out = ttk.Frame(io)
        io.add(out, weight=3)
        ttk.Label(out, text="Output", style="Dim.TLabel").pack(anchor="w")
        self.out_wrap = ttk.Frame(out, style="Panel.TFrame", padding=1)
        self.out_wrap.pack(fill="both", expand=True, pady=(3, 0))
        self.output_text = tk.Text(self.out_wrap, wrap="word", relief="flat",
                                   padx=10, pady=8, borderwidth=0)
        osb = ttk.Scrollbar(self.out_wrap, orient="vertical", command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=osb.set)
        self.output_text.pack(side="left", fill="both", expand=True)
        osb.pack(side="right", fill="y")
        self.table_wrap = ttk.Frame(self.out_wrap, style="Panel.TFrame")
        self.table = ttk.Treeview(self.table_wrap, show="headings")
        self.tsb = ttk.Scrollbar(self.table_wrap, orient="vertical", command=self.table.yview)
        self.tsbx = ttk.Scrollbar(self.table_wrap, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=self.tsb.set, xscrollcommand=self.tsbx.set)
        self.tsb.pack(side="right", fill="y")
        self.tsbx.pack(side="bottom", fill="x")
        self.table.pack(side="left", fill="both", expand=True)
        self.image_lbl = tk.Label(self.out_wrap, borderwidth=0, anchor="center")

        self.status = ttk.Label(self, text="Ready.", style="Dim.TLabel",
                                padding=(16, 4, 16, 8), wraplength=1100)
        self.status.pack(side="bottom", fill="x", before=pane)
        self._recolour()

    def _recolour(self):
        c = self.c
        for t in (self.input_text, self.output_text):
            t.configure(background=c["field"], foreground=c["field_text"],
                        insertbackground=c["accent"], insertwidth=2,
                        selectbackground=c["accent"], selectforeground=c["accent_text"],
                        font=(self.mono, 10), highlightthickness=1,
                        highlightbackground=c["field_border"], highlightcolor=c["accent"])
        self.explain.configure(background=c["panel"], foreground=c["text"],
                               font=(self.ui, 10), highlightthickness=0,
                               selectbackground=c["sel"], selectforeground=c["text"])
        self.image_lbl.configure(background=c["panel"])
        self.explain.tag_configure("h", font=(self.ui, 10, "bold"), foreground=c["accent"])
        self.output_text.tag_configure("dim", foreground=c["dim"])
        # classic tk widgets that ttk styles do not reach: menus and the
        # guide window, if it is open
        for menu in self.menus:
            try:
                menu.configure(bg=c["panel"], fg=c["text"], activebackground=c["sel"],
                               activeforeground=c["text"], borderwidth=0)
            except tk.TclError:
                pass
        if self.guide_win is not None:
            try:
                self.guide_win.configure(bg=c["bg"])
                self.guide_txt.configure(background=c["panel"], foreground=c["text"],
                                         selectbackground=c["sel"], selectforeground=c["text"])
                self.guide_txt.tag_configure("h1", foreground=c["accent"])
            except tk.TclError:
                self.guide_win = self.guide_txt = None

    # --------------------------------------------------------- mouse wheel

    _SCROLLABLE = ("Text", "Treeview", "Listbox", "Canvas")
    _WHEEL_SEQS = ("<MouseWheel>", "<Shift-MouseWheel>",
                   "<Button-4>", "<Button-5>", "<Shift-Button-4>", "<Shift-Button-5>")

    def _bind_wheel(self):
        """One wheel handler for the whole window.

        Tk's own class bindings scroll whichever widget has focus by a
        whole page-ish jump, and on Windows and macOS the deltas mean
        different things. This replaces them: the widget under the pointer
        scrolls, in small steps, and a scrollable child never hands the
        wheel on to a scrollable parent."""
        for cls in self._SCROLLABLE:
            for seq in self._WHEEL_SEQS:
                self.root.bind_class(cls, seq, self._on_wheel)
        for seq in self._WHEEL_SEQS:
            self.root.bind_all(seq, self._on_wheel, add="+")
        for seq in ("<Button-6>", "<Button-7>"):        # X11 horizontal wheel, Tk 8.7+
            try:
                self.root.bind_all(seq, self._on_wheel, add="+")
            except tk.TclError:
                pass

    def _on_wheel(self, event):
        tkc = self.root.tk
        num = getattr(event, "num", 0)
        if isinstance(num, str):
            num = 0
        if num in (4, 6):
            notches = -1.0
        elif num in (5, 7):
            notches = 1.0
        else:
            delta = getattr(event, "delta", 0) or 0
            if not delta:
                return None
            # macOS reports small raw units; Windows and X11 report multiples
            # of 120 (precision touchpads send fractions, hence the carry).
            notches = -float(delta) if sys.platform == "darwin" else -delta / 120.0
        horizontal = num in (6, 7) or bool(getattr(event, "state", 0) & 0x0001)
        try:
            path = str(tkc.call("winfo", "containing", event.x_root, event.y_root))
        except tk.TclError:
            path = ""
        if not path:
            path = str(getattr(event.widget, "_w", event.widget))
        try:
            while path and str(tkc.call("winfo", "class", path)) not in self._SCROLLABLE:
                path = str(tkc.call("winfo", "parent", path))
        except tk.TclError:
            return None
        if not path:
            return None
        per_notch = 1.0 if sys.platform == "darwin" else 3.0    # lines per click
        want = notches * per_notch
        if self._wheel_rem[0] == path:
            want += self._wheel_rem[1]
        steps = int(want)
        self._wheel_rem = (path, want - steps)
        if steps:
            try:
                tkc.call(path, "xview" if horizontal else "yview", "scroll", steps, "units")
            except tk.TclError:
                pass
        return "break"

    # ------------------------------------------------------------- sidebar

    def _populate(self):
        term = self.search_var.get().strip()
        hits = search(term)
        ids = {t.id for t in hits}
        self.tree.delete(*self.tree.get_children())
        cats = by_category()
        order = [c for c in CATEGORY_ORDER if c in cats]
        for cat in order:
            tools = [t for t in cats[cat] if t.id in ids]
            if not tools:
                continue
            node = self.tree.insert("", "end", iid="cat:" + cat, text=cat, open=True)
            for t in tools:
                self.tree.insert(node, "end", iid=t.id, text="   " + t.name)
        if term:
            self.status.configure(text=f'{len(hits)} tool(s) match "{term}".')

    def _on_select(self, _=None):
        if self._selecting:
            return
        sel = self.tree.selection()
        if not sel or sel[0].startswith("cat:"):
            return
        self.select_tool(sel[0])

    def select_tool(self, tool_id):
        """Show a tool. Guarded, because setting the tree selection fires the
        selection event again and would otherwise recurse forever."""
        if tool_id not in REGISTRY or self._selecting:
            return
        if self.streaming:
            self.stop_stream()
        self._selecting = True
        try:
            self.tool = REGISTRY[tool_id]
            current = self.tree.selection()
            if self.tree.exists(tool_id) and (not current or current[0] != tool_id):
                self.tree.selection_set(tool_id)
                self.tree.see(tool_id)
            self._render_tool()
        finally:
            self._selecting = False

    # ---------------------------------------------------------- tool panel

    def _render_tool(self):
        t = self.tool
        self.name_lbl.configure(text=t.name)
        self.sum_lbl.configure(text=t.summary)
        self._render_explain()
        if t.security:
            self.warn_lbl.configure(text="Caution:  " + t.security)
            # anchored to the paned window, which is always packed - the
            # parameters row is not, on tools that have no settings
            self.warn_lbl.pack(fill="x", padx=14, pady=(8, 0), before=self.io)
        else:
            self.warn_lbl.pack_forget()
        self.hint_suggest = None
        self.hint_btn.pack_forget()
        self.solve_btn.pack_forget()
        self.hint_lbl.configure(text=self.IDLE_HINT)
        self._render_params()
        self._render_input()
        self._render_buttons()
        self.clear_output()
        self.after_idle(self._fix_io_sash)
        self.status.configure(text=CATEGORY_BLURB.get(t.category, "Ready."))

    def _fix_io_sash(self):
        """Keep the input box a usable size. The divider stays where you put
        it, but a tool with a tall settings block must not squeeze it to
        nothing on the way past."""
        try:
            height = self.io.winfo_height()
            if height < 140:
                return
            pos = self.io.sashpos(0)
            if self.tool and self.tool.input_kind == "none":
                if pos > 24:
                    self.io.sashpos(0, 1)
                return
            floor, ceiling = 132, int(height * 0.62)
            if pos < floor or pos > ceiling:
                self.io.sashpos(0, max(floor, min(int(height * 0.36), ceiling)))
        except Exception:
            pass

    def _render_explain(self):
        t = self.tool
        open_ = self.explain_open.get()
        self.explain_btn.configure(text=("Hide how this works" if open_
                                         else "How this works"))
        self.explain.configure(state="normal")
        self.explain.delete("1.0", "end")
        self.explain.insert("end", t.explain or t.summary)
        if t.example:
            self.explain.insert("end", "\n\nExample\n", "h")
            self.explain.insert("end", t.example)
        self.explain.configure(state="disabled")
        self.explain.update_idletasks()
        try:      # shrink the panel to the text, within reason
            lines = int(self.explain.count("1.0", "end", "displaylines")[0])
            self.explain.configure(height=max(3, min(12, lines)))
        except Exception:
            pass
        if open_:
            self.explain_frame.pack(fill="x", padx=14, pady=(4, 0), after=self.explain_btn)
        else:
            self.explain_frame.pack_forget()

    def _toggle_explain(self):
        self.explain_open.set(not self.explain_open.get())
        self._render_explain()

    def _render_params(self):
        # Rebuilt inside a throwaway child frame: a grid that has held widgets
        # keeps its row sizes afterwards, which would leave a gap on any tool
        # that has fewer settings than the one before it.
        if self.params_inner is not None:
            self.params_inner.destroy()
            self.params_inner = None
        self.param_vars.clear()
        self.param_holders = {}
        t = self.tool
        if not t.params:
            self.params_frame.pack_forget()
            return
        self.params_frame.pack(fill="x", before=self.io)
        self.params_inner = ttk.Frame(self.params_frame)
        self.params_inner.pack(fill="x")
        self.param_holders = {}
        for i in range(3):
            self.params_inner.grid_columnconfigure(i, weight=1)
        for p in t.params:
            holder = ttk.Frame(self.params_inner)
            self.param_holders[p.name] = holder
            self._param_widget(holder, p)
        for name, var in self.param_vars.items():
            if isinstance(var, (tk.StringVar, tk.BooleanVar)):
                var.trace_add("write", lambda *a: self._layout_params())
        self._layout_params()

    def _param_values(self):
        out = {}
        for name, var in self.param_vars.items():
            try:
                out[name] = (var.get("1.0", "end-1c") if isinstance(var, tk.Text) else var.get())
            except Exception:
                out[name] = ""
        return out

    def _layout_params(self):
        """Place the settings that apply, and hide the ones that do not -
        re-flowing so hiding one never leaves a hole in the row."""
        if not self.tool or not getattr(self, "param_holders", None):
            return
        vals = self._param_values()
        col = row = 0
        for p in self.tool.params:
            holder = self.param_holders.get(p.name)
            if holder is None:
                continue
            show = True
            if p.visible_when:
                try:
                    show = bool(p.visible_when(vals))
                except Exception:
                    show = True
            if not show:
                holder.grid_remove()
                continue
            holder.grid(row=row, column=col, sticky="ew", padx=(0, 14), pady=3)
            col += 1
            if col >= 3 or p.kind == "multiline":
                col = 0
                row += 1

    def _param_widget(self, holder, p: Param):
        c = self.c
        if p.kind == "bool":
            var = tk.BooleanVar(value=bool(p.default))
            w = ttk.Checkbutton(holder, text=p.label, variable=var)
            w.pack(anchor="w")
        elif p.kind == "multiline":
            ttk.Label(holder, text=p.label, style="Field.TLabel").pack(anchor="w")
            var = tk.StringVar(value=str(p.default or ""))
            box = tk.Text(holder, height=4, wrap="none", relief="flat", padx=8, pady=6,
                          background=c["field"], foreground=c["field_text"],
                          insertbackground=c["accent"], insertwidth=2, font=(self.mono, 9),
                          selectbackground=c["accent"], selectforeground=c["accent_text"],
                          highlightthickness=1, highlightbackground=c["field_border"],
                          highlightcolor=c["accent"])
            box.insert("1.0", str(p.default or ""))
            box.pack(fill="x")
            var = box                                   # read straight from the widget
            w = box
        elif p.kind == "choice":
            ttk.Label(holder, text=p.label, style="Field.TLabel").pack(anchor="w")
            choices = p.choices
            if callable(choices):        # re-read every time, e.g. audio devices
                try:
                    choices = list(choices())
                except Exception:
                    choices = []
            choices = list(choices or [])
            default = str(p.default) if p.default is not None else ""
            if default and default not in choices:
                choices = [default] + choices
            var = tk.StringVar(value=default or (choices[0] if choices else ""))
            w = ttk.Combobox(holder, textvariable=var, values=choices, state="readonly")
            w.pack(fill="x")
        elif p.kind in ("file", "files", "folder", "savefile"):
            ttk.Label(holder, text=p.label, style="Field.TLabel").pack(anchor="w")
            # an empty "save into" box is pre-filled with the default save folder
            var = tk.StringVar(value=str(p.default or
                                         (default_save_dir() if p.kind == "folder" else "")))
            pick_row = ttk.Frame(holder)
            pick_row.pack(fill="x")
            e = ttk.Entry(pick_row, textvariable=var)
            e.pack(side="left", fill="x", expand=True)
            ttk.Button(pick_row, text="…", width=3,
                       command=lambda v=var, k=p.kind: self._pick(v, k)).pack(side="left", padx=(4, 0))
            w = e
        else:
            ttk.Label(holder, text=p.label, style="Field.TLabel").pack(anchor="w")
            var = tk.StringVar(value="" if p.default is None else str(p.default))
            w = ttk.Entry(holder, textvariable=var,
                          show="*" if p.kind == "password" else "")
            w.pack(fill="x")
        self.param_vars[p.name] = var
        if p.help:
            Tip(w, p.help, c)
            ttk.Label(holder, text=p.help, style="Dim.TLabel", wraplength=280,
                      font=(self.ui, 8)).pack(anchor="w")

    def _pick(self, var, kind):
        if kind == "folder":                    # every folder setting is somewhere to save
            path = filedialog.askdirectory(initialdir=default_save_dir())
        elif kind == "savefile":
            path = filedialog.asksaveasfilename(initialdir=default_save_dir())
        else:
            types = self.tool.input_types if self.tool else None
            path = (filedialog.askopenfilename(filetypes=types) if types
                    else filedialog.askopenfilename())
        if path:
            var.set(path)

    def _render_input(self):
        t = self.tool
        if t.input_kind == "none":
            for w in (self.input_head, self.file_row, self.file_info,
                      self.hint_bar, self.text_wrap):
                w.pack_forget()
            return
        self.input_head.configure(text=t.input_label)
        self.input_head.pack(anchor="w")
        # Forget everything first: re-packing a widget that is already managed
        # updates its options but leaves it where it was in the packing order,
        # and the order is what decides who gets squeezed out of a short pane.
        for w in (self.file_row, self.file_info, self.hint_bar, self.text_wrap):
            w.pack_forget()
        if t.input_kind in ("file", "folder"):
            self.file_row.pack(fill="x", pady=(3, 0))
            self.file_info.pack(side="bottom", fill="x", pady=(4, 0))
            self._schedule_file_info()
        else:
            self.hint_bar.pack(side="bottom", fill="x", pady=(5, 0))
            self.text_wrap.pack(fill="both", expand=True, pady=(3, 0))
            self._update_hint()

    def _render_buttons(self):
        for w in self.dir_btns.winfo_children():
            w.destroy()
        self.start_btn = self.stop_btn = None
        t = self.tool
        if t.stream:
            self.start_btn = ttk.Button(self.dir_btns, text=t.start_label,
                                        style="Accent.TButton", command=self.start_stream)
            self.start_btn.pack(side="left", padx=(0, 8))
            self.stop_btn = ttk.Button(self.dir_btns, text=t.stop_label,
                                       command=self.stop_stream, state="disabled")
            self.stop_btn.pack(side="left", padx=(0, 8))
            if self.streaming:      # re-rendered mid-stream, e.g. by a theme toggle
                self.start_btn.configure(state="disabled")
                self.stop_btn.configure(state="normal")
            return
        first = True
        for direction, label, fn in t.directions():
            b = ttk.Button(self.dir_btns, text=label,
                           style="Accent.TButton" if first else "TButton",
                           command=lambda d=direction: self.run(d))
            b.pack(side="left", padx=(0, 8))
            first = False
        self.chain_btn.configure(state="normal")

    # --------------------------------------------------------------- input

    def open_file(self):
        t = self.tool
        if t and t.input_kind == "folder":
            path = filedialog.askdirectory(title="Choose a folder")
            if path:
                self.file_var.set(path)
            return
        types = (t.input_types if t and t.input_types else None)
        path = (filedialog.askopenfilename(title="Choose a file", filetypes=types)
                if types else filedialog.askopenfilename(title="Choose a file"))
        if not path:
            return
        if t and t.input_kind == "file":
            self.file_var.set(path)
            return
        try:
            with open(path, "rb") as fh:
                raw = fh.read(2 * 1024 * 1024)
            try:
                body = raw.decode("utf-8")
            except UnicodeDecodeError:
                body = raw.decode("latin-1")
                self.status.configure(text=f"{os.path.basename(path)} is not UTF-8 text — "
                                           "loaded byte-for-byte as Latin-1.")
            self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", body)
        except OSError as exc:
            messagebox.showerror(APP, f"Could not read that file:\n{exc}")

    IDLE_HINT = ("Paste or type anything here. Cryptex will say what it looks like. "
                 "Ctrl+O opens a file, Ctrl+F finds a tool.")

    def _schedule_hint(self, _=None):
        if self.hint_job is not None:
            try:
                self.after_cancel(self.hint_job)
            except Exception:
                pass
        self.hint_job = self.after(400, self._update_hint)

    def _update_hint(self):
        """Look at what is in the input box and say what it appears to be."""
        self.hint_job = None
        if not self.tool or self.tool.input_kind not in ("text",):
            return
        text = self.input_text.get("1.0", "end-1c")
        guess = None
        if text.strip():
            try:
                from .identify import quick_identify
                guess = quick_identify(text[:100_000])
            except Exception:
                guess = None
        self._show_solve(bool(text.strip()) and self.tool.id != "auto-solve")
        if not guess:
            self.hint_suggest = None
            self.hint_btn.pack_forget()
            self.hint_lbl.configure(
                text=("Nothing recognisable - press Auto-solve and it will try everything."
                      if text.strip() else self.IDLE_HINT))
            return
        name, conf, advice, tool_id = guess
        self.hint_suggest = tool_id
        msg = f"This looks like {name} ({conf}% sure)."
        if tool_id == self.tool.id:
            msg += "  You are on the right tool - press " + \
                   (self.tool.directions()[0][1] if self.tool.directions() else "the button") + "."
        elif advice:
            msg += "  " + advice
        self.hint_lbl.configure(text=msg)
        if tool_id and tool_id in REGISTRY and tool_id != self.tool.id:
            self.hint_btn.configure(text="Open " + REGISTRY[tool_id].name)
            self.hint_btn.pack(side="right", padx=(8, 6), pady=4)
        else:
            self.hint_btn.pack_forget()

    def _show_solve(self, show):
        if show:
            self.solve_btn.pack(side="right", padx=(8, 8), pady=4)
        else:
            self.solve_btn.pack_forget()

    def _take_solve(self):
        """Hand whatever is in the input box to the auto-solver and run it."""
        text = self.input_text.get("1.0", "end-1c")
        if not text.strip():
            return
        self.select_tool("auto-solve")
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", text)
        self._update_hint()
        self.run("action")

    def _take_hint(self):
        """Carry the text across to whichever tool the detection suggested."""
        if not self.hint_suggest or self.hint_suggest not in REGISTRY:
            return
        text = self.input_text.get("1.0", "end-1c")
        self.select_tool(self.hint_suggest)
        if self.tool.input_kind == "text":
            self.input_text.delete("1.0", "end")
            self.input_text.insert("1.0", text)
            self._update_hint()
        self.status.configure(text=f"Switched to {self.tool.name} and brought your text with it.",
                              style="Good.TLabel")

    def _schedule_file_info(self):
        self.after(60, self._update_file_info)

    def _update_file_info(self):
        """Say what the chosen file actually is, rather than leaving you to
        find out by pressing the button."""
        if not self.tool or self.tool.input_kind not in ("file", "folder"):
            return
        path = self.file_var.get().strip()
        if not path:
            self.file_info.configure(text="No file chosen yet.")
            return
        if not os.path.exists(path):
            self.file_info.configure(text="That path does not exist.")
            return
        if os.path.isdir(path):
            try:
                n = sum(len(f) for _r, _d, f in os.walk(path))
                self.file_info.configure(text=f"Folder - {n} file(s) inside.")
            except OSError:
                self.file_info.configure(text="Folder.")
            return
        size = os.path.getsize(path)
        bits = [f"{size:,} bytes"]
        try:
            with open(path, "rb") as fh:
                head = fh.read(64)
            from .analysis import _identify_magic
            kind = _identify_magic(head)
            if kind:
                bits.append(kind)
        except OSError:
            pass
        self.file_info.configure(text=" - ".join(bits))
        ext = os.path.splitext(path)[1].lower()
        from .audio import MEDIA_EXT
        if ext in MEDIA_EXT:
            def probe(p=path):
                try:
                    from .audio import media_info
                    info = media_info(p)
                except Exception:
                    info = ""
                if info:
                    self.q.put(("fileinfo", p, " - ".join(bits + [info])))
            threading.Thread(target=probe, daemon=True).start()

    def _gather(self, direction):
        kwargs = {}
        for p in self.tool.params_for(direction):
            var = self.param_vars.get(p.name)
            if var is None:
                continue
            raw = var.get("1.0", "end-1c") if isinstance(var, tk.Text) else var.get()
            if p.kind == "int":
                try:
                    raw = int(str(raw).strip() or p.default or 0)
                except ValueError:
                    raise ToolError(f'"{p.label}" needs a whole number.')
            elif p.kind == "float":
                try:
                    raw = float(str(raw).strip() or p.default or 0)
                except ValueError:
                    raise ToolError(f'"{p.label}" needs a number.')
            kwargs[p.name] = raw
        return kwargs

    def _input_value(self):
        t = self.tool
        if t.input_kind == "none":
            return None
        if t.input_kind in ("file", "folder"):
            return self.file_var.get().strip()
        return self.input_text.get("1.0", "end-1c")

    # ----------------------------------------------------------- execution

    def start_stream(self):
        """Run a streaming tool: a generator that yields a Result whenever it
        has something new. Stop is a flag the generator watches, so it can
        close the sound device and finish the picture on its way out."""
        if self.busy or not self.tool or not self.tool.stream:
            return
        t = self.tool
        try:
            kwargs = self._gather("action")
        except ToolError as exc:
            self.show_error(str(exc))
            return
        self.stop_event = threading.Event()
        self.busy = True
        self.streaming = True
        if self.start_btn:
            self.start_btn.configure(state="disabled")
        if self.stop_btn:
            self.stop_btn.configure(state="normal")
        self.status.configure(text="Starting...", style="Dim.TLabel")
        ev = self.stop_event

        def worker():
            try:
                for out in t.stream(ev, **kwargs):
                    self.q.put(("ok", as_result(out)))
                    if ev.is_set():
                        pass
            except ToolError as exc:
                self.q.put(("err", str(exc)))
            except Exception as exc:                      # noqa: BLE001
                self.q.put(("crash", f"{type(exc).__name__}: {exc}", traceback.format_exc()))
            finally:
                self.q.put(("streamdone", None))

        threading.Thread(target=worker, daemon=True).start()

    def stop_stream(self):
        if getattr(self, "stop_event", None) is not None:
            self.stop_event.set()
        if self.stop_btn:
            self.stop_btn.configure(state="disabled")
        self.status.configure(text="Stopping...", style="Dim.TLabel")

    def run_primary(self):
        if self.tool and self.tool.stream:
            (self.stop_stream if self.streaming else self.start_stream)()
            return
        dirs = self.tool.directions() if self.tool else []
        if dirs:
            self.run(dirs[0][0])

    def run(self, direction):
        if self.busy or not self.tool:
            return
        t = self.tool
        fn = dict((d, f) for d, _l, f in t.directions()).get(direction)
        if fn is None:
            return
        try:
            kwargs = self._gather(direction)
            value = self._input_value()
        except ToolError as exc:
            self.show_error(str(exc))
            return
        self.busy = True
        self.status.configure(text="Working…", style="Dim.TLabel")
        self.root.config(cursor="watch")

        def worker():
            try:
                out = fn(**kwargs) if t.input_kind == "none" else fn(value, **kwargs)
                self.q.put(("ok", as_result(out)))
            except ToolError as exc:
                self.q.put(("err", str(exc)))
            except Exception as exc:                       # noqa: BLE001
                self.q.put(("crash", f"{type(exc).__name__}: {exc}",
                            traceback.format_exc()))

        threading.Thread(target=worker, daemon=True).start()

    def _pump(self):
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "fileinfo":
                    if self.file_var.get().strip() == msg[1]:
                        self.file_info.configure(text=msg[2])
                    continue
                if msg[0] == "streamdone":
                    self.busy = False
                    self.streaming = False
                    self.root.config(cursor="")
                    if self.start_btn:
                        self.start_btn.configure(state="normal")
                    if self.stop_btn:
                        self.stop_btn.configure(state="disabled")
                    continue
                if not self.streaming:
                    self.busy = False
                    self.root.config(cursor="")
                if msg[0] == "ok":
                    self.show_result(msg[1])
                elif msg[0] == "err":
                    self.show_error(msg[1])
                else:
                    self.show_error(msg[1])
                    try:
                        with open(os.path.join(app_dir(), "cryptex-errors.log"), "a",
                                  encoding="utf-8") as fh:
                            fh.write(msg[2] + "\n")
                    except Exception:
                        pass
        except queue.Empty:
            pass
        finally:
            # whatever went wrong showing one result, keep pumping - otherwise
            # nothing is ever shown again and the app looks hung
            self.after(80, self._pump)

    # -------------------------------------------------------------- output

    def clear_output(self):
        self.output_text.pack_forget()
        self.table_wrap.pack_forget()
        self.image_lbl.pack_forget()
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.pack(side="left", fill="both", expand=True)
        self.last_result = None

    def clear(self):
        self.input_text.delete("1.0", "end")
        self.file_var.set("")
        self.clear_output()
        self.status.configure(text="Cleared.", style="Dim.TLabel")

    def show_error(self, message):
        self.clear_output()
        self.output_text.insert("1.0", message)
        self.status.configure(text=message.split("\n")[0], style="Bad.TLabel")

    def show_result(self, res: Result):
        live_image = (self.streaming and res.image_path
                      and self.image_lbl.winfo_ismapped())
        if not live_image:
            self.clear_output()
        self.last_result = res
        if res.prefer == "text":
            body = res.text or ""
            if res.rows:
                width = max((len(str(r[0])) for r in res.rows), default=0)
                detail = "\n".join(f"{str(r[0]):<{width}}   " + "  ".join(str(v) for v in r[1:])
                                    for r in res.rows)
                body = (body + "\n\n" if body else "") + detail
            self.output_text.insert("1.0", body)
        elif res.image_path and os.path.isfile(res.image_path):
            self._show_image(res.image_path, reuse=live_image)
        elif res.rows:
            self._show_table(res)
        else:
            self.output_text.insert("1.0", res.text)
        if self.streaming and self.output_text.winfo_ismapped():
            self.output_text.see("end")
        parts = []
        if res.warn:
            parts.append("Caution:  " + res.warn)
        if res.note:
            parts.append(res.note)
        if res.file_path:
            parts.append(f"Saved: {res.file_path}")
        # A caution that comes with a result is amber, not red. Red is for
        # something that actually failed, which goes through show_error.
        self.status.configure(text="   ".join(parts) or "Done.",
                              style="Warn.TLabel" if res.warn else "Good.TLabel")

    def _show_table(self, res: Result):
        self.output_text.pack_forget()
        headers = res.headers or [f"Column {i+1}" for i in range(len(res.rows[0]))]
        self.table.configure(columns=[f"c{i}" for i in range(len(headers))])
        widths = [0] * len(headers)
        for i, h in enumerate(headers):
            self.table.heading(f"c{i}", text=h)
            widths[i] = max(len(str(h)) * 8, 60)
        self.table.delete(*self.table.get_children())
        for r in res.rows:
            vals = [("" if v is None else str(v)) for v in r]
            self.table.insert("", "end", values=vals)
            for i, v in enumerate(vals[:len(widths)]):
                widths[i] = max(widths[i], min(len(v) * 7 + 18, 430))
        for i in range(len(headers)):
            self.table.column(f"c{i}", width=widths[i], minwidth=40,
                              stretch=(i == len(headers) - 1), anchor="w")
        self.table_wrap.pack(fill="both", expand=True)


    def _show_image(self, path, reuse=False):
        try:
            from PIL import Image, ImageTk
        except ImportError:
            self.output_text.insert("1.0", f"Picture written to:\n{path}")
            return
        if not reuse:
            self.output_text.pack_forget()
            self.update_idletasks()
        box_w = max(320, self.out_wrap.winfo_width() - 12)
        box_h = max(240, self.out_wrap.winfo_height() - 12)
        img = Image.open(path)
        scale = min(box_w / img.width, box_h / img.height, 3.0)
        if scale != 1.0:
            img = img.resize((max(1, int(img.width * scale)), max(1, int(img.height * scale))),
                             Image.LANCZOS)
        self.photo = ImageTk.PhotoImage(img)
        self.image_lbl.configure(image=self.photo)
        if not reuse:
            self.image_lbl.pack(fill="both", expand=True)
        self.image_lbl.bind("<Double-Button-1>", lambda e: self._open_path(path))

    def _open_path(self, path):
        try:
            webbrowser.open("file://" + os.path.abspath(path))
        except Exception:
            pass

    def copy_output(self):
        res = self.last_result
        text = ""
        if res:
            if res.text:
                text = res.text
            elif res.rows:
                text = "\n".join("\t".join(str(v) for v in r) for r in res.rows)
            elif res.file_path:
                text = res.file_path
        else:
            text = self.output_text.get("1.0", "end-1c")
        if not text:
            self.status.configure(text="Nothing to copy.", style="Dim.TLabel")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status.configure(text=f"Copied {len(text)} characters.", style="Good.TLabel")

    def chain(self):
        res = self.last_result
        text = res.text if res and res.text else self.output_text.get("1.0", "end-1c")
        if not text.strip():
            self.status.configure(text="There is no output to feed back in.", style="Dim.TLabel")
            return
        if self.tool.input_kind in ("file", "folder", "none"):
            self.status.configure(text="This tool takes a file, not text — "
                                       "pick a text tool first.", style="Dim.TLabel")
            return
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", text)
        self.clear_output()
        self._update_hint()
        self.status.configure(text="Output moved into the input box. "
                                   "Pick the next tool and go again.", style="Good.TLabel")

    def save_output(self):
        res = self.last_result
        if res and res.file_path and os.path.isfile(res.file_path):
            self.status.configure(text=f"Already written to {res.file_path}", style="Good.TLabel")
            return
        data = None
        if res and res.data is not None:
            data = res.data
        text = (res.text if res and res.text else self.output_text.get("1.0", "end-1c"))
        if data is None and not text:
            self.status.configure(text="Nothing to save.", style="Dim.TLabel")
            return
        name = (res.suggested_name if res and res.suggested_name else "cryptex-output.txt")
        path = filedialog.asksaveasfilename(initialfile=name, initialdir=default_save_dir())
        if not path:
            return
        try:
            if data is not None:
                with open(path, "wb") as fh:
                    fh.write(data)
            else:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(text)
            self.status.configure(text=f"Saved to {path}", style="Good.TLabel")
        except OSError as exc:
            messagebox.showerror(APP, f"Could not save:\n{exc}")

    # ---------------------------------------------------------------- misc

    def choose_save_dir(self):
        """Where everything Cryptex writes goes unless a tool is told otherwise."""
        path = filedialog.askdirectory(title="Default save folder",
                                       initialdir=default_save_dir())
        if not path:
            return
        self.settings["save_dir"] = path
        self._save_settings()
        self._refresh_folder_fields()
        self.status.configure(text=f"Files will be saved to {path}.", style="Good.TLabel")

    def reset_save_dir(self):
        self.settings.pop("save_dir", None)
        self._save_settings()
        self._refresh_folder_fields()
        self.status.configure(text=f"Files will be saved to {downloads_dir()}.",
                              style="Good.TLabel")

    def _refresh_folder_fields(self):
        """Re-point any 'Save into' box on the current tool at the new default."""
        if not self.tool:
            return
        for p in self.tool.params:
            var = self.param_vars.get(p.name)
            if p.kind == "folder" and not p.default and isinstance(var, tk.StringVar):
                var.set(default_save_dir())

    def toggle_theme(self):
        self.dark = not self.dark
        self.c = theme.apply(self.root, self.dark)
        self.theme_btn.configure(text="Light" if self.dark else "Dark")
        self._recolour()
        if self.tool:
            self._render_tool()

    def show_about(self):
        messagebox.showinfo(
            f"About {APP}",
            f"{APP} {VERSION}\n\nAn encoder, decoder and cryptography toolbox.\n"
            f"{len(REGISTRY)} tools across {len(by_category())} categories.\n\n"
            "Everything runs on this machine. Nothing is uploaded anywhere, and no "
            "key, password or file leaves the computer.")

    def show_guide(self):
        if self.guide_win is not None:
            try:
                self.guide_win.lift()
                return
            except tk.TclError:
                self.guide_win = self.guide_txt = None
        win = tk.Toplevel(self.root)
        win.title("What can Cryptex do?")
        win.geometry("760x620")
        win.configure(bg=self.c["bg"])
        txt = tk.Text(win, wrap="word", padx=18, pady=16, relief="flat",
                      background=self.c["panel"], foreground=self.c["text"],
                      selectbackground=self.c["sel"], selectforeground=self.c["text"],
                      highlightthickness=0, font=(self.ui, 10))
        sb = ttk.Scrollbar(win, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.guide_win, self.guide_txt = win, txt

        def _gone(_e=None, w=win):
            if self.guide_win is w:
                self.guide_win = self.guide_txt = None
        win.bind("<Destroy>", _gone, add="+")
        txt.tag_configure("h1", font=(self.ui, 13, "bold"), foreground=self.c["accent"],
                          spacing1=12, spacing3=4)
        txt.tag_configure("b", font=(self.ui, 10, "bold"))
        txt.insert("end", "Cryptex in one paragraph\n", "h1")
        txt.insert("end",
                   "Three different things get called 'encryption' in ordinary speech, and "
                   "Cryptex keeps them apart. Encoding changes how data is written and hides "
                   "nothing. Hashing produces a fingerprint and cannot be reversed at all. "
                   "Encryption hides the contents and needs a key to undo. If you are not sure "
                   "which one you are holding, open 'What is this?' and paste it in.\n\n"
                   "Anything Cryptex writes - saved output, encrypted files, pictures, "
                   "WAVs - goes to your Downloads folder unless you pick another place "
                   "under File > Default save folder.\n")
        for cat, tools in by_category().items():
            txt.insert("end", f"\n{cat}\n", "h1")
            txt.insert("end", CATEGORY_BLURB.get(cat, "") + "\n\n")
            for t in tools:
                txt.insert("end", f"  {t.name}", "b")
                txt.insert("end", f" — {t.summary}\n")
        txt.configure(state="disabled")


def launch():
    root = tk.Tk()
    App(root)
    root.mainloop()
