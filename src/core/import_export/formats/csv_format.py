import csv
import io
from datetime import datetime, timezone
from typing import Dict, Iterable, List


class CSVVaultFormat:
    name = "csv"
    fieldnames = ["title", "username", "password", "url", "notes", "category", "tags"]
    aliases = {
        "name": "title",
        "title": "title",
        "username": "username",
        "login": "username",
        "password": "password",
        "url": "url",
        "website": "url",
        "extra": "notes",
        "notes": "notes",
        "grouping": "category",
        "folder": "category",
        "category": "category",
        "tags": "tags",
    }

    def serialize_rows(self, rows: Iterable[Dict[str, str]], *, include_metadata: bool = True) -> str:
        output = io.StringIO(newline="")
        if include_metadata:
            output.write("# CryptoSafe CSV Export\n")
            output.write(f"# exported_at={datetime.now(timezone.utc).isoformat()}\n")
            output.write("# fields=title,username,password,url,notes,category,tags\n")
        writer = csv.DictWriter(output, fieldnames=self.fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: str(row.get(field, "") or "") for field in self.fieldnames})
        return output.getvalue()

    def parse_rows(self, payload: str) -> List[Dict[str, str]]:
        data_lines = [
            line
            for line in str(payload or "").splitlines()
            if not line.lstrip().startswith("#")
        ]
        reader = csv.DictReader(io.StringIO("\n".join(data_lines)))
        if not reader.fieldnames:
            return []
        return [
            self._normalize_row(row)
            for row in reader
        ]

    def _normalize_row(self, row: Dict[str, str]) -> Dict[str, str]:
        normalized = {field: "" for field in self.fieldnames}
        for key, value in row.items():
            target = self.aliases.get(str(key or "").strip().lower())
            if target:
                normalized[target] = str(value or "")
        return normalized