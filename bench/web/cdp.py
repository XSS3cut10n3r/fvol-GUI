"""Minimal Chrome DevTools Protocol driver for UI checks of `fvol serve` (headless chromium).

Collects console errors / uncaught exceptions so UI regressions show up as failures.
Run it through bench/scripts/limit.sh (chromium is memory hungry)."""

import base64
import json
import os
import shutil
import subprocess
import time
import urllib.request

import websocket  # websocket-client


class Chrome:
    def __init__(self, width=1440, height=900, port=9339, profile="/home/user/fvol/testdata/scratch/webui/chrome-profile"):
        shutil.rmtree(profile, ignore_errors=True)
        os.makedirs(profile, exist_ok=True)
        self.proc = subprocess.Popen(
            ["chromium", "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run", "--no-default-browser-check",
             f"--remote-debugging-port={port}", f"--window-size={width},{height}", f"--user-data-dir={profile}",
             "--force-device-scale-factor=1", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
                page = next(t for t in tabs if t["type"] == "page")
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("chromium did not start")
        self.ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=60, suppress_origin=True)
        self.n = 0
        self.errors = []
        self.console = []
        self.width, self.height = width, height
        for m in ("Page.enable", "Runtime.enable", "Log.enable"):
            self.send(m)

    def _event(self, msg):
        m = msg.get("method")
        p = msg.get("params", {})
        if m == "Runtime.exceptionThrown":
            d = p["exceptionDetails"]
            self.errors.append((d.get("exception", {}).get("description") or d.get("text", "")) + f" @{d.get('url','')}:{d.get('lineNumber')}")
        elif m == "Runtime.consoleAPICalled" and p.get("type") in ("error", "warning", "assert"):
            self.errors.append("console." + p["type"] + ": " + " ".join(str(a.get("value", a.get("description", ""))) for a in p.get("args", [])))
        elif m == "Log.entryAdded" and p["entry"]["level"] in ("error",):
            e = p["entry"]
            # network 4xx on purpose-probed URLs are fine; keep everything else
            self.errors.append("log: " + e.get("text", "") + " " + e.get("url", ""))

    def send(self, method, params=None):
        self.n += 1
        mid = self.n
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})
            self._event(msg)

    def eval(self, expr, await_promise=True):
        r = self.send("Runtime.evaluate", {"expression": expr, "awaitPromise": await_promise, "returnByValue": True})
        if "exceptionDetails" in r:
            raise RuntimeError("eval failed: " + json.dumps(r["exceptionDetails"])[:500])
        return r.get("result", {}).get("value")

    def pump(self, secs):
        end = time.time() + secs
        self.ws.settimeout(0.05)
        while time.time() < end:
            try:
                self._event(json.loads(self.ws.recv()))
            except websocket.WebSocketTimeoutException:
                pass
        self.ws.settimeout(60)

    def goto(self, url, settle=1.0):
        self.send("Page.navigate", {"url": url})
        self.pump(settle)

    def wait(self, expr, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if self.eval(f"!!({expr})"):
                return True
            self.pump(0.1)
        raise RuntimeError(f"timeout waiting for {expr}")

    def key(self, key, code=None, mods=0, text=None):
        """mods: 1 alt, 2 ctrl, 4 meta, 8 shift"""
        vk = {"Enter": 13, "Escape": 27, "ArrowDown": 40, "ArrowUp": 38, "ArrowLeft": 37, "ArrowRight": 39, "Tab": 9, "Backspace": 8, "PageDown": 34, "PageUp": 33, "Home": 36, "End": 35}.get(key)
        if vk is None and len(key) == 1:
            vk = ord(key.upper())
        base = {"key": key, "code": code or ("Key" + key.upper() if len(key) == 1 and key.isalpha() else key), "modifiers": mods, "windowsVirtualKeyCode": vk, "nativeVirtualKeyCode": vk}
        down = dict(base, type="keyDown")
        if text is None and len(key) == 1 and not (mods & 6):
            text = key
        if text:
            down["text"] = text
        self.send("Input.dispatchKeyEvent", down)
        self.send("Input.dispatchKeyEvent", dict(base, type="keyUp"))
        self.pump(0.05)

    def type(self, s):
        for ch in s:
            self.key(ch)

    def click(self, selector, index=0):
        box = self.eval(f"(() => {{ const e = document.querySelectorAll({json.dumps(selector)})[{index}]; if (!e) return null; e.scrollIntoView({{block:'nearest'}}); const r = e.getBoundingClientRect(); return [r.left + r.width/2, r.top + r.height/2]; }})()")
        if not box:
            raise RuntimeError(f"no element {selector}[{index}]")
        for t in ("mousePressed", "mouseReleased"):
            self.send("Input.dispatchMouseEvent", {"type": t, "x": box[0], "y": box[1], "button": "left", "clickCount": 1})
        self.pump(0.1)

    def resize(self, w, h):
        self.send("Emulation.setDeviceMetricsOverride", {"width": w, "height": h, "deviceScaleFactor": 1, "mobile": False})
        self.width, self.height = w, h
        self.pump(0.3)

    def shot(self, path):
        r = self.send("Page.captureScreenshot", {"format": "png"})
        with open(path, "wb") as f:
            f.write(base64.b64decode(r["data"]))
        return path

    def close(self):
        try:
            self.ws.close()
        finally:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except Exception:
                self.proc.kill()
