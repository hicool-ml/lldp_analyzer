"""Reusable UI widgets — Windows native style InfoCard."""

import tkinter as tk
from ui.styles import COLORS


class InfoCard(tk.LabelFrame):
    """Card with title + key-value rows, native Windows look."""

    def __init__(self, parent, title: str, **kwargs):
        super().__init__(
            parent, text=f"  {title}  ",
            bg=COLORS["surface"], fg=COLORS["text"],
            font=("Segoe UI", 11, "bold"),
            bd=1, relief=tk.GROOVE,
            padx=10, pady=8,
            **kwargs,
        )
        self._row_count = 0
        self._rows: list[dict] = []  # store (label_name, value_label, row_frame)

    def add_row(self, name: str, value: str = "\u2014"):
        """Add a label/value row. Returns the value Label widget so callers
        can later `.config(text=...)` it to update display."""
        row = tk.Frame(self, bg=COLORS["surface"])
        row.pack(fill=tk.X, pady=1)

        name_label = tk.Label(row, text=name, bg=COLORS["surface"], fg=COLORS["text2"],
                              font=("Segoe UI", 9), width=14, anchor=tk.W)
        name_label.pack(side=tk.LEFT)

        val_color = COLORS["success"] if value not in ("\u2014", "", None) else COLORS["text2"]
        value_label = tk.Label(
            row, text=str(value),
            bg=COLORS["surface"], fg=val_color,
            font=("Segoe UI", 9, "bold"), anchor=tk.W,
            wraplength=350, justify=tk.LEFT,
        )
        value_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._rows.append({
            "frame": row,
            "name_label": name_label,
            "value_label": value_label,
        })
        self._row_count += 1
        return value_label

    def refresh_theme(self):
        """Update widget colors to match current theme."""
        from ui.styles import COLORS, is_dark_mode
        try:
            dark = is_dark_mode()
            self.config(bg=COLORS["surface"], fg=COLORS["text"],
                           font=("Segoe UI", 11, "bold"))
            for r in self._rows:
                r["frame"].config(bg=COLORS["surface"])
                r["name_label"].config(bg=COLORS["surface"], fg=COLORS["text2"])
                current_text = r["value_label"].cget("text")
                val_color = COLORS["success"] if current_text not in ("\u2014", "", None) else COLORS["text2"]
                r["value_label"].config(bg=COLORS["surface"], fg=val_color)
        except Exception:
            pass
