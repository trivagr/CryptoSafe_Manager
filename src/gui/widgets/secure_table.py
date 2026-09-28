import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Dict, List, Optional


class SecureTable(ttk.Frame):
    """Таблица для отображения записей хранилища."""

    def __init__(self, parent, columns: List[Dict[str, Any]]):
        super().__init__(parent)

        self.columns = columns
        self.data: List[Dict[str, Any]] = []
        self._sort_state: Dict[str, bool] = {}
        self._column_order = [col["id"] for col in columns]
        self._dragged_column_id: Optional[str] = None

        self.tree = ttk.Treeview(
            self,
            columns=[col["id"] for col in columns],
            show="headings",
            selectmode="extended",
            style="Vault.Treeview",
        )

        for col in columns:
            self.tree.heading(
                col["id"],
                text=col["label"],
                command=lambda column_id=col["id"]: self._sort_by(column_id),
            )
            self.tree.column(col["id"], width=col.get("width", 100))
        self.tree.configure(displaycolumns=self._column_order)

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._supports_row_tags = True
        try:
            self.tree.tag_configure("even", background="#252526", foreground="#d4d4d4")
            self.tree.tag_configure("odd", background="#2d2d30", foreground="#d4d4d4")
        except (AttributeError, tk.TclError):
            self._supports_row_tags = False

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.tree.bind("<ButtonPress-1>", self._begin_column_drag, add="+")
        self.tree.bind("<ButtonRelease-1>", self._finish_column_drag, add="+")

    def _sort_by(self, column_id: str):
        if not self.data:
            return

        reverse = not self._sort_state.get(column_id, False)
        self._sort_state = {column_id: reverse}
        self.data.sort(key=lambda row: self._sort_key(row.get(column_id)), reverse=reverse)
        self.set_data(self.data)

    def _sort_key(self, value: Any):
        if value is None:
            return ""
        return str(value).lower()

    def set_data(self, data: List[Dict[str, Any]]):
        """Заполнить таблицу данными."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.data = list(data)

        for i, row in enumerate(self.data):
            values = [row.get(col["id"], "") for col in self.columns]
            if getattr(self, "_supports_row_tags", False):
                self.tree.insert("", "end", iid=str(i), values=values, tags=("odd" if i % 2 else "even",))
            else:
                self.tree.insert("", "end", iid=str(i), values=values)

    def get_selected(self) -> Optional[Dict[str, Any]]:
        """Получить выбранную запись."""
        selection = self.tree.selection()
        if selection:
            index = int(selection[0])
            return self.data[index]
        return None

    def get_selected_items(self) -> List[Dict[str, Any]]:
        """Получить все выбранные записи."""
        selected_items: List[Dict[str, Any]] = []
        for item_id in self.tree.selection():
            index = int(item_id)
            selected_items.append(self.data[index])
        return selected_items

    def select_row_at_y(self, y: int) -> Optional[Dict[str, Any]]:
        """Выбрать строку по координате Y внутри таблицы."""
        item_id = self.tree.identify_row(y)
        if not item_id:
            return None
        self.tree.selection_set(item_id)
        self.tree.focus(item_id)
        return self.get_selected()

    def ensure_row_selected_at_y(self, y: int) -> Optional[Dict[str, Any]]:
        """Выбрать строку под курсором, не сбрасывая текущую группу выделения."""
        item_id = self.tree.identify_row(y)
        if not item_id:
            return None
        if item_id not in self.tree.selection():
            self.tree.selection_set(item_id)
        self.tree.focus(item_id)
        return self.get_selected()

    def bind_context_menu(self, callback: Callable):
        """Привязать обработчик контекстного меню к строкам таблицы."""
        self.tree.bind("<Button-3>", callback, add="+")

    def bind_primary_click(self, callback: Callable):
        """Привязать обработчик левого клика к таблице."""
        self.tree.bind("<Button-1>", callback, add="+")

    def _begin_column_drag(self, event):
        if self.tree.identify_region(event.x, event.y) != "heading":
            self._dragged_column_id = None
            return
        self._dragged_column_id = self._identify_column_id(event.x)

    def _finish_column_drag(self, event):
        if self._dragged_column_id is None:
            return
        if self.tree.identify_region(event.x, event.y) != "heading":
            self._dragged_column_id = None
            return

        target_column_id = self._identify_column_id(event.x)
        if target_column_id is not None:
            self._reorder_display_columns(self._dragged_column_id, target_column_id)
        self._dragged_column_id = None

    def _identify_column_id(self, x: int) -> Optional[str]:
        column_ref = self.tree.identify_column(x)
        if not column_ref:
            return None
        try:
            column_index = int(column_ref.lstrip("#")) - 1
        except ValueError:
            return None
        if column_index < 0 or column_index >= len(self._column_order):
            return None
        return self._column_order[column_index]

    def _reorder_display_columns(self, source_column_id: str, target_column_id: str):
        if source_column_id == target_column_id:
            return
        if source_column_id not in self._column_order or target_column_id not in self._column_order:
            return

        updated_order = [column_id for column_id in self._column_order if column_id != source_column_id]
        target_index = updated_order.index(target_column_id)
        updated_order.insert(target_index, source_column_id)
        self._column_order = updated_order
        self.tree.configure(displaycolumns=self._column_order)

    def get_cell_at(self, x: int, y: int) -> Optional[Dict[str, Any]]:
        """Получить информацию о ячейке по координатам внутри таблицы."""
        item_id = self.tree.identify_row(y)
        column_ref = self.tree.identify_column(x)
        if not item_id or not column_ref:
            return None

        try:
            column_index = int(column_ref.lstrip("#")) - 1
        except ValueError:
            return None

        if column_index < 0 or column_index >= len(self._column_order):
            return None

        column_id = self._column_order[column_index]

        return {
            "item_id": item_id,
            "column_id": column_id,
            "row": self.data[int(item_id)],
        }

    def clear(self):
        """Очистить таблицу."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.data = []