from src.core.vault.entry_manager import EntryManager
from src.gui.models.vault_table_model import VaultTableModel


class VaultService:

    def __init__(self, db, key_manager, event_system):

        self.entry_manager = EntryManager(
            db_connection=db,
            key_manager=key_manager,
            event_system=event_system
        )

    # =====================================================
    # GET ALL
    # =====================================================

    def get_all_entries(self):

        entries = self.entry_manager.get_all_entries()

        result = []

        for entry in entries:

            result.append({
                "id": entry.id,
                "title": entry.title,
                "username": entry.username,
                "password": entry.password,
                "url": entry.url,
                "notes": entry.notes,
                "created_at": entry.created_at,
                "updated_at": entry.updated_at,
            })

        return result

    # =====================================================
    # ADD
    # =====================================================

    def add_entry(self, data):

        entry = VaultTableModel(
            title=data.get("title", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            url=data.get("url", ""),
            notes=data.get("notes", "")
        )

        self.entry_manager.create_entry(entry)

    # =====================================================
    # UPDATE
    # =====================================================

    def update_entry(self, entry_id, data):

        entry = VaultTableModel(
            id=entry_id,
            title=data.get("title", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            url=data.get("url", ""),
            notes=data.get("notes", "")
        )

        self.entry_manager.update_entry(entry)

    # =====================================================
    # DELETE
    # =====================================================

    def delete_entry(self, entry_id):

        self.entry_manager.delete_entry(entry_id)

    # =====================================================
    # SEARCH
    # =====================================================

    def search_entries(self, text):

        text = text.lower()

        result = []

        for row in self.get_all_entries():

            if (
                text in row["title"].lower()
                or text in row["username"].lower()
                or text in row["url"].lower()
            ):
                result.append(row)

        return result