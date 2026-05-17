# Log Parser — OOP-based log classification and reporting system.
# Written: May 8th, 2026. Author: Night-pool.
# Naming convention: "x_" prefix for inputs, "y_" prefix for outputs (Engineering Mathematics style).

import os
import psycopg2
from dotenv import load_dotenv
load_dotenv()

# ─────────────────────────────────────────────
#  BASE CLASS
# ─────────────────────────────────────────────

class BaseLog:
    def __init__(me, timestamp: str, level: str, message: str) -> None:
        me.timestamp = timestamp
        me.level = level
        me.message = message

    def is_suspicious(me) -> bool:
        return me.level in ("CRITICAL", "WARNING")

    def summary(me) -> str:
        return (
            f"Level:     {me.level}\n"
            f"Timestamp: {me.timestamp}\n"
            f"Message:   {me.message}\n"
        )

    def __repr__(me) -> str:
        return f"BaseLog(level={me.level!r}, timestamp={me.timestamp!r}, message={me.message!r})"


# ─────────────────────────────────────────────
#  SUBCLASSES
# ─────────────────────────────────────────────

class NetworkLog(BaseLog):
    def __init__(me, timestamp: str, level: str, message: str, src_ip: str, dest_ip: str) -> None:
        super().__init__(timestamp, level, message)
        me.src_ip = src_ip
        me.dest_ip = dest_ip

    def summary(me) -> str:
        return (
                super().summary() +
                f"Source IP: {me.src_ip}\n"
                f"Dest IP:   {me.dest_ip}\n"
        )

    def is_internal(me) -> bool:
        return me.src_ip.startswith("192.168.")


class AuthLog(BaseLog):
    def __init__(me, timestamp: str, level: str, message: str, user: str, attempts: int) -> None:
        super().__init__(timestamp, level, message)
        me.user = user
        me.attempts = attempts

    def summary(me) -> str:
        return (
                super().summary() +
                f"User:     {me.user}\n"
                f"Attempts: {me.attempts}\n"
        )

    def is_brute_force(me) -> bool:
        return me.attempts > 5 and me.level == "CRITICAL"


class SystemLog(BaseLog):
    def __init__(me, timestamp: str, level: str, message: str, process: str, exit_code: int) -> None:
        super().__init__(timestamp, level, message)
        me.process = process
        me.exit_code = exit_code

    def summary(me) -> str:
        return (
                super().summary() +
                f"Process:   {me.process}\n"
                f"Exit Code: {me.exit_code}\n"
        )

    def is_crashed(me) -> bool:
        return me.exit_code != 0


class CriticalNetworkLog(NetworkLog, AuthLog):
    """Combined network + auth log for high-severity correlated events."""

    def __init__(me, timestamp: str, level: str, message: str,
                 src_ip: str, dest_ip: str, user: str, attempts: int) -> None:
        BaseLog.__init__(me, timestamp, level, message)
        me.src_ip = src_ip
        me.dest_ip = dest_ip
        me.user = user
        me.attempts = attempts

    def summary(me) -> str:
        return (
            f"[CRITICAL NET+AUTH]\n"
            f"Level:     {me.level}\n"
            f"Timestamp: {me.timestamp}\n"
            f"Message:   {me.message}\n"
            f"Source IP: {me.src_ip}\n"
            f"Dest IP:   {me.dest_ip}\n"
            f"User:      {me.user}\n"
            f"Attempts:  {me.attempts}\n"
        )


# ─────────────────────────────────────────────
#  LOG FILE READER
# ─────────────────────────────────────────────

def read_log_file(x_filepath: str) -> list:
    """
    Reads a plain-text log file.
    Expected line format:
        TYPE | TIMESTAMP | LEVEL | MESSAGE | [extra fields...]

    Field order per type:
        network:          TYPE | TIMESTAMP | LEVEL | MESSAGE | SRC_IP | DEST_IP
        auth:             TYPE | TIMESTAMP | LEVEL | MESSAGE | USER | ATTEMPTS
        system:           TYPE | TIMESTAMP | LEVEL | MESSAGE | PROCESS | EXIT_CODE
        critical_network: TYPE | TIMESTAMP | LEVEL | MESSAGE | SRC_IP | DEST_IP | USER | ATTEMPTS

    Lines starting with '#' are treated as comments and skipped.
    """
    y_raw_logs = []

    if not os.path.exists(x_filepath):
        print(f"[ERROR] File not found: {x_filepath}")
        return y_raw_logs

    with open(x_filepath, "r") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            try:
                log_type = parts[0].lower()
                if log_type == "network" and len(parts) >= 6:
                    y_raw_logs.append({
                        "type": "network", "timestamp": parts[1], "level": parts[2],
                        "message": parts[3], "src_ip": parts[4], "dest_ip": parts[5]
                    })
                elif log_type == "auth" and len(parts) >= 6:
                    y_raw_logs.append({
                        "type": "auth", "timestamp": parts[1], "level": parts[2],
                        "message": parts[3], "user": parts[4], "attempts": int(parts[5])
                    })
                elif log_type == "system" and len(parts) >= 6:
                    y_raw_logs.append({
                        "type": "system", "timestamp": parts[1], "level": parts[2],
                        "message": parts[3], "process": parts[4], "exit_code": int(parts[5])
                    })
                elif log_type == "critical_network" and len(parts) >= 8:
                    y_raw_logs.append({
                        "type": "critical_network", "timestamp": parts[1], "level": parts[2],
                        "message": parts[3], "src_ip": parts[4], "dest_ip": parts[5],
                        "user": parts[6], "attempts": int(parts[7])
                    })
                else:
                    print(f"[WARN] Line {line_num}: unrecognised format or missing fields — skipped.")
            except (ValueError, IndexError) as e:
                print(f"[WARN] Line {line_num}: parse error ({e}) — skipped.")

    return y_raw_logs


# ─────────────────────────────────────────────
#  PARSER
# ─────────────────────────────────────────────

def parse_log(x_raw_logs: list) -> list:
    y_ripe_logs = []
    for i, log in enumerate(x_raw_logs):
        try:
            t = log["type"]
            if t == "network":
                y_ripe_logs.append(NetworkLog(
                    log["timestamp"], log["level"], log["message"],
                    log["src_ip"], log["dest_ip"]
                ))
            elif t == "auth":
                y_ripe_logs.append(AuthLog(
                    log["timestamp"], log["level"], log["message"],
                    log["user"], log["attempts"]
                ))
            elif t == "system":
                y_ripe_logs.append(SystemLog(
                    log["timestamp"], log["level"], log["message"],
                    log["process"], log["exit_code"]
                ))
            elif t == "critical_network":
                y_ripe_logs.append(CriticalNetworkLog(
                    log["timestamp"], log["level"], log["message"],
                    log["src_ip"], log["dest_ip"], log["user"], log["attempts"]
                ))
        except KeyError as e:
            print(f"[ERROR] Log #{i + 1} missing key {e} — skipped.")
    return y_ripe_logs


# ─────────────────────────────────────────────
#  COUNTERS & HELPERS
# ─────────────────────────────────────────────

def count_enumerator(xx_log: list) -> tuple:
    suspicious_count = 0
    crashed_count = 0
    brute_force_count = 0
    for i_log in xx_log:
        if i_log.is_suspicious():
            suspicious_count += 1
        if isinstance(i_log, SystemLog) and i_log.is_crashed():
            crashed_count += 1
        if isinstance(i_log, AuthLog) and i_log.is_brute_force():
            brute_force_count += 1
    return suspicious_count, crashed_count, brute_force_count


def ordinal(n: int) -> str:
    suffix = "th" if 11 <= n % 100 <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


# ─────────────────────────────────────────────
#  REPORT
# ─────────────────────────────────────────────

def generate_report(xx_ripe_logs: list) -> None:
    print("\n======== Log Report ========\n")
    for i, i_log in enumerate(xx_ripe_logs):
        print(f"--- {ordinal(i + 1)} log ---")
        print(i_log.summary())

    print("======= Log Synopsis =======\n")
    print(f"Total logs:            {len(xx_ripe_logs)}")
    x, y, z = count_enumerator(xx_ripe_logs)
    print(f"Suspicious logs:       {x}")
    print(f"Crashed processes:     {y}")
    print(f"Brute force attempts:  {z}")

    print("\n======= Flagged Events ======\n")
    flagged = False
    for i_log in xx_ripe_logs:
        if isinstance(i_log, AuthLog) and i_log.is_brute_force():
            print(f"[BRUTE FORCE] {i_log.timestamp} — user '{i_log.user}' ({i_log.attempts} attempts)")
            flagged = True
        if isinstance(i_log, SystemLog) and i_log.is_crashed():
            print(f"[CRASH]       {i_log.timestamp} — process '{i_log.process}' exited {i_log.exit_code}")
            flagged = True
        if isinstance(i_log, NetworkLog) and i_log.is_internal() and i_log.level == "CRITICAL":
            print(f"[INTERNAL THREAT] {i_log.timestamp} — src {i_log.src_ip} → {i_log.dest_ip}")
            flagged = True
    if not flagged:
        print("No flagged events.")


# ─────────────────────────────────────────────
#  BUILT-IN TEST DATA
# ─────────────────────────────────────────────

BUILTIN_LOGS = [
    {"type": "network", "timestamp": "10:01", "level": "WARNING", "message": "High traffic volume",
     "src_ip": "192.168.1.10", "dest_ip": "8.8.8.8"},
    {"type": "auth", "timestamp": "10:02", "level": "CRITICAL", "message": "Login failed", "user": "admin",
     "attempts": 9},
    {"type": "system", "timestamp": "10:03", "level": "INFO", "message": "Scheduled backup", "process": "backup.py",
     "exit_code": 0},
    {"type": "network", "timestamp": "10:04", "level": "INFO", "message": "DNS query", "src_ip": "10.0.0.5",
     "dest_ip": "1.1.1.1"},
    {"type": "auth", "timestamp": "10:05", "level": "WARNING", "message": "Unknown user login", "user": "guest",
     "attempts": 2},
    {"type": "system", "timestamp": "10:06", "level": "CRITICAL", "message": "Process crash", "process": "core.py",
     "exit_code": 1},
    {"type": "network", "timestamp": "10:07", "level": "CRITICAL", "message": "Port scan detected",
     "src_ip": "192.168.1.42", "dest_ip": "10.0.0.1"},
    {"type": "critical_network", "timestamp": "10:08", "level": "CRITICAL", "message": "Brute force from internal IP",
     "src_ip": "192.168.1.99", "dest_ip": "10.0.0.1", "user": "root", "attempts": 12},
]


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────


def connect_db():
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )
    return conn

def save_logs_to_db(conn, xx_ripe_logs: list) -> None:
    cursor = conn.cursor()
    for log in xx_ripe_logs:
        cursor.execute("""
            INSERT INTO logs (type, timestamp, level, message, src_ip, dest_ip, username, attempts, process, exit_code)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            type(log).__name__,
            log.timestamp,
            log.level,
            log.message,
            getattr(log, 'src_ip',    None),
            getattr(log, 'dest_ip',   None),
            getattr(log, 'user',      None),
            getattr(log, 'attempts',  None),
            getattr(log, 'process',   None),
            getattr(log, 'exit_code', None),
        ))
    conn.commit()
    print(f"[DB] {len(xx_ripe_logs)} logs inserted successfully!")



def main() -> None:
    print("╔══════════════════════════════╗")
    print("║   Log Parser — Night-pool    ║")
    print("╚══════════════════════════════╝")
    print("\nOptions:")
    print("  1. Load from a log file (.txt)")
    print("  2. Run built-in test data")
    choice = input("\nEnter choice (1 or 2): ").strip()

    if choice == "1":
        filepath = input("Enter path to log file: ").strip()
        x_raw_logs = read_log_file(filepath)
        if not x_raw_logs:
            print("[ERROR] No valid logs found. Exiting.")
            return
    else:
        print("\n[INFO] Using built-in test data.")
        x_raw_logs = BUILTIN_LOGS

    y_ripe_logs = parse_log(x_raw_logs)
    generate_report(y_ripe_logs)

    conn = connect_db()
    save_logs_to_db(conn, y_ripe_logs)
    conn.close()

if __name__ == "__main__":
    main()