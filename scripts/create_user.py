"""Create or reset a console user.  python scripts/create_user.py <username> <role> [password]
Roles: admin | analyst | auditor | demo. Without a password a random one is generated and printed once."""
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "brain"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
from glasswall_brain import db as dbm  # noqa: E402

ROLES = {"admin", "analyst", "auditor", "demo"}


def main() -> None:
    user, role = sys.argv[1], sys.argv[2]
    if role not in ROLES:
        sys.exit(f"role must be one of {sorted(ROLES)}")
    pw = sys.argv[3] if len(sys.argv) > 3 else secrets.token_urlsafe(12)
    import hashlib
    salt = secrets.token_hex(16)
    h = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()
    con = dbm.init()
    con.execute("INSERT OR REPLACE INTO users VALUES (?,?,?,?)", (user, role, h, salt))
    con.commit()
    print(f"user {user} ({role}) password: {pw}")


if __name__ == "__main__":
    main()
