class VaultController:

    def __init__(self, service, model):
        self.service = service
        self.model = model

    def refresh(self):
        data = self.service.get_all()
        self.model.load(data)

    def search(self, text):
        data = self.service.get_all()
        filtered = [x for x in data if text.lower() in str(x).lower()]
        self.model.load(filtered)