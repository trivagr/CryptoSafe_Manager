from src.core.vault.entry_manager import EntryManager


class VaultService:

    def __init__(
            self,
            db,
            key_manager,
            event_system
    ):

        self.entry_manager = EntryManager(
            db_connection=db,
            key_manager=key_manager,
            event_system=event_system
        )

    # =====================================================
    # GET ALL
    # =====================================================

    def get_all_entries(self):

        entries = (
            self.entry_manager
            .get_all_entries()
        )

        result = []

        for entry in entries:

            result.append({

                "id":
                    entry.get(
                        "id"
                    ),

                "title":
                    entry.get(
                        "title",
                        ""
                    ),

                "username":
                    entry.get(
                        "username",
                        ""
                    ),

                "password":
                    entry.get(
                        "password",
                        ""
                    ),

                "url":
                    entry.get(
                        "url",
                        ""
                    ),

                "notes":
                    entry.get(
                        "notes",
                        ""
                    ),

                "category":
                    entry.get(
                        "category",
                        ""
                    ),

                "created_at":
                    entry.get(
                        "created_at",
                        ""
                    ),

                "updated_at":
                    entry.get(
                        "updated_at",
                        ""
                    )

            })

        return result

    # =====================================================
    # ADD
    # =====================================================

    def add_entry(
            self,
            data
    ):

        entry = {

            "title":
                data.get(
                    "title",
                    ""
                ),

            "username":
                data.get(
                    "username",
                    ""
                ),

            "password":
                data.get(
                    "password",
                    ""
                ),

            "url":
                data.get(
                    "url",
                    ""
                ),

            "notes":
                data.get(
                    "notes",
                    ""
                ),

            "category":
                data.get(
                    "category",
                    ""
                )
        }

        return (
            self.entry_manager
            .create_entry(
                entry
            )
        )

    # =====================================================
    # UPDATE
    # =====================================================

    def update_entry(
            self,
            entry_id,
            data
    ):

        entry = {

            "title":
                data.get(
                    "title",
                    ""
                ),

            "username":
                data.get(
                    "username",
                    ""
                ),

            "password":
                data.get(
                    "password",
                    ""
                ),

            "url":
                data.get(
                    "url",
                    ""
                ),

            "notes":
                data.get(
                    "notes",
                    ""
                ),

            "category":
                data.get(
                    "category",
                    ""
                )
        }

        self.entry_manager.update_entry(
            entry_id,
            entry
        )

    # =====================================================
    # DELETE
    # =====================================================

    def delete_entry(
            self,
            entry_id
    ):

        self.entry_manager.delete_entry(
            entry_id
        )

    # =====================================================
    # SEARCH
    # =====================================================

    def search_entries(
            self,
            text
    ):

        text = text.lower()

        result = []

        for row in self.get_all_entries():

            title = row.get(
                "title",
                ""
            ).lower()

            username = row.get(
                "username",
                ""
            ).lower()

            url = row.get(
                "url",
                ""
            ).lower()

            if (

                    text in title
                    or text in username
                    or text in url

            ):

                result.append(
                    row
                )

        return result