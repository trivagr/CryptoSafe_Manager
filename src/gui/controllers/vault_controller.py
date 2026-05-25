class VaultController:

    def __init__(self, service, model):
        self.service = service
        self.model = model

    def refresh(self):
        self.model.reload()

    def search(self, text: str):
        if not text:
            self.model.reload()
            return

        ids = self.service.search(text)
        self.model.rows = [
            r for r in self.service.get_all_entries()
            if r["id"] in ids
        ]
        self.model.layoutChanged.emit()