"""Explain evidence links without assigning application or USB activity to a user."""


def classify_timeline(seed, candidates, identities):
    names_by_uid = {}
    uids_by_name = {}
    for uid, name in identities:
        names_by_uid.setdefault(uid, set()).add(name)
        uids_by_name.setdefault(name, set()).add(uid)

    def identity(row):
        uid = row["uid"]
        account = row["account"]
        if uid is None and account.startswith("uid:"):
            uid = account[4:]
        if uid is not None:
            return {uid}, names_by_uid.get(uid, set())
        if account.startswith("app:") or account in ("unattributed", "unknown"):
            return set(), set()
        mapped = uids_by_name.get(account, set())
        return mapped if len(mapped) == 1 else set(), {account}

    seed_uids, seed_names = identity(seed)
    result = []
    for row in candidates:
        if (seed["boot_id"] and row["boot_id"]
                and seed["boot_id"] != row["boot_id"]):
            continue
        if row["id"] == seed["id"]:
            relation = "Selected event"
        else:
            row_uids, row_names = identity(row)
            same_user = (bool(seed_uids & row_uids) if seed_uids and row_uids
                         else bool(seed_names & row_names))
            if same_user and (seed["kind"] == "login_failure" or row["kind"] == "login_failure"):
                relation = "Same account · login unverified"
            elif (same_user and seed["session"] and row["session"]
                    and seed["session"] == row["session"]
                    and seed["boot_id"] and seed["boot_id"] == row["boot_id"]):
                relation = "Same user and session"
            elif same_user:
                relation = "Same user"
            else:
                relation = "Host context · user unverified"
        result.append(dict(row, relation=relation))
    return sorted(result, key=lambda row: (
        row["timestamp"], 0 if isinstance(row["id"], int) else 1, row["id"]))
