#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WakeDeck - ローカルLAN内の Ubuntu Server 電源管理ツール (Windows用)

やること:
  電源ON  : Wake on LAN マジックパケットを送信する
  電源OFF : SSHで接続して `sudo poweroff` を実行する
  再起動  : SSHで接続して `sudo reboot` を実行する
  状態監視: ping + SSHポート(22)で 起動済み/起動中/停止中 を自動判定する
  SSH端末 : 選択したサーバーへ別ウィンドウのSSHターミナルを開く (v1.0.0)

設計:
  - WoL / ping / 状態判定は Python標準ライブラリのみ
  - SSHのパスワード認証には paramiko を使用 (pip install paramiko)
    paramiko が無い環境では Windows標準の ssh.exe + 鍵認証 + パスワードなしsudo
    へ自動フォールバックする
  - SSHパスワードは Windows では DPAPI で暗号化して config.json に保存する
    (同じWindowsユーザーでしか復号できない。他OSでは base64 の難読化のみ)
  - GUI (Tkinter) と CLI (--on / --off / --reboot / --status) の両対応
    ショートカットやタスクスケジューラからも使える
  - v1.0.0: 複数サーバーを一覧で管理 (追加/編集/削除/複数選択/一括ON・OFF)
    設定ファイルは v2 形式 {"servers": [...]}。v1 の1台形式は自動で移行する
  - v1.0.0: 選択したサーバーへ別ウィンドウでSSHターミナルを開く
    (Windows Terminal があれば wt.exe 経由、無ければ cmd の start 経由)

設定ファイル: このスクリプト/exe と同じフォルダの config.json (ポータブル)

【読み方ガイド】
  構成は上から順に: 設定まわり (Config / 読み書き / 暗号化) → ネットワーク部品
  (ping / ポート確認 / WoL) → SSH実行 → 電源操作の組み立て → 検索・スキャン
  → ターミナル起動 → 鍵登録 → GUI → CLI の順に並んでいる。

  よく出てくる名前:
    cfg   … 対象サーバーの設定1台分 (Config クラス)。関数の引数で頻出する
    uid   … GUIの一覧の行に振った内部ID (連番)。サーバー本体ではなく行の番号
    log   … ログ出力用の関数。「画面や標準出力へ1行出す」役割で差し替え可能
    state … 検索/スキャンダイアログで結果を持ち回すための辞書
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import platform
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field, asdict
from pathlib import Path

APP_NAME = "WakeDeck"
APP_VERSION = "1.0.1"
IS_WINDOWS = platform.system() == "Windows"

# ---------------------------------------------------------------------------
# パス
# ---------------------------------------------------------------------------

def app_dir() -> Path:
    """exe化(PyInstaller)されていれば exe のフォルダ、そうでなければ .py のフォルダ"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def resource_path(relative_path: str) -> Path:
    """通常実行とPyInstaller onefile実行の両方で同梱リソースを探す"""
    bundle_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return bundle_dir / relative_path


def default_config_path() -> Path:
    """config.json の標準の保存場所 (このスクリプトと同じフォルダ) を返す"""
    return app_dir() / "config.json"


# ---------------------------------------------------------------------------
# パスワード保護 (Windows: DPAPI / その他: base64難読化)
# ---------------------------------------------------------------------------

class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    """Windows の DPAPI を呼ぶ内部関数。protect=True で暗号化、False で復号する"""
    crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    in_buf = ctypes.create_string_buffer(data, len(data))
    in_blob = _DataBlob(len(data), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = _DataBlob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob))
    if not ok:
        raise OSError("DPAPI failed")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def protect_secret(plain: str) -> str:
    """保存用にパスワードを保護する。接頭辞で方式を示す: dpapi: / b64:"""
    if not plain:
        return ""
    if IS_WINDOWS:
        enc = _dpapi(plain.encode("utf-8"), protect=True)
        return "dpapi:" + base64.b64encode(enc).decode("ascii")
    return "b64:" + base64.b64encode(plain.encode("utf-8")).decode("ascii")


def unprotect_secret(stored: str) -> str:
    """protect_secret で暗号化した文字列を元に戻す。失敗したら空文字を返す"""
    if not stored:
        return ""
    try:
        if stored.startswith("dpapi:"):
            raw = base64.b64decode(stored[6:])
            return _dpapi(raw, protect=False).decode("utf-8")
        if stored.startswith("b64:"):
            return base64.b64decode(stored[4:]).decode("utf-8")
    except Exception:
        return ""
    return ""


# ---------------------------------------------------------------------------
# 設定
# ---------------------------------------------------------------------------

@dataclass
class Config:
    server_name: str = "Ubuntu Server"
    host: str = ""                        # IPアドレス or ホスト名
    mac_address: str = ""                 # 例: AA:BB:CC:DD:EE:FF
    broadcast_address: str = ""           # 空なら host から /24 で自動計算 + 255.255.255.255
    wol_port: int = 9
    wol_password: str = ""                # SecureOn パスワード (任意, 6バイトを16進で 例: 010203040506)
    ssh_user: str = ""
    ssh_port: int = 22
    ssh_password_protected: str = ""      # protect_secret() 済みの値。平文は保存しない
    ssh_key_file: str = ""                # 秘密鍵パス (任意。指定時は鍵認証を優先)
    os_type: str = "linux"                # "linux" (Ubuntu等) / "windows"
    windows_method: str = "ssh"           # Windows対象の電源OFF方式: "ssh" (OpenSSH) / "rpc" (shutdown.exe)
    monitor_only: bool = False            # 旧来の明示フラグ (互換用。通常は SSHユーザー名が空なら自動で監視のみになる)
    status_port: int = 0                  # 監視のみ用: 状態確認に使うTCPポート (0=pingのみ。例: RDP 3389)
    check_interval_sec: int = 4

    # -- 永続化 -------------------------------------------------------------
    @classmethod
    def load(cls, path: Path) -> "Config":
        """設定ファイルを読み込んで中身を返す"""
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
                return cls(**{k: v for k, v in data.items() if k in known})
            except Exception:
                pass
        return cls()

    def save(self, path: Path) -> None:
        """設定ファイルへ中身を書き出す"""
        path.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2),
                        encoding="utf-8")

    # -- 派生プロパティ -------------------------------------------------------
    @property
    def ssh_password(self) -> str:
        return unprotect_secret(self.ssh_password_protected)

    @ssh_password.setter
    def ssh_password(self, plain: str) -> None:
        self.ssh_password_protected = protect_secret(plain)

    def is_monitor_only(self) -> bool:
        """実効的に「監視のみ」かどうかを返す。
        明示フラグが無くても SSHユーザー名が未入力なら自動的に監視のみになる
        (SSH/RPC を使えない機器を IP+MAC だけで登録できるようにするため)。
        Windows + RPC方式だけは SSHユーザー不要で電源操作できるので例外。"""
        if self.monitor_only:
            return True
        if self.is_windows and self.windows_method == "rpc":
            return False
        return not self.ssh_user.strip()

    @property
    def is_configured(self) -> bool:
        if self.is_monitor_only():
            # 監視のみ: WoLと状態表示に必要な IP + MAC だけで成立
            return bool(self.host and self.mac_address)
        if self.os_type == "windows" and self.windows_method == "rpc":
            # RPC方式はSSHユーザー不要 (実行中のWindowsユーザーの資格情報を使う)
            return bool(self.host and self.mac_address)
        return bool(self.host and self.mac_address and self.ssh_user)

    @property
    def is_windows(self) -> bool:
        return self.os_type == "windows"

    @property
    def check_port(self) -> int:
        """状態判定で見るポート (0 = ポートを見ず ping のみで判定)。
        監視のみ: status_port (未指定なら0) / RPC方式のWindows: SMB(445) / それ以外: SSHポート"""
        if self.is_monitor_only():
            return int(self.status_port or 0)
        if self.is_windows and self.windows_method == "rpc":
            return 445
        return int(self.ssh_port)



# ---------------------------------------------------------------------------
# 複数サーバーの設定ファイル (v2形式 / v1形式から自動移行)
# ---------------------------------------------------------------------------

CONFIG_VERSION = 2


def load_servers(path: Path) -> tuple[list[Config], int]:
    """
    config.json を読み、(サーバーのリスト, 状態確認間隔秒) を返す。
    - v2形式: {"version": 2, "check_interval_sec": 4, "servers": [{...}, ...]}
    - v1形式: 単一サーバーの dict → 1要素のリストとして読み込む (自動移行)
    - ファイルが無い/壊れている: 空リスト
    """
    if not path.exists():
        return [], 4
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return [], 4
    if isinstance(data, dict) and isinstance(data.get("servers"), list):
        known = set(Config.__dataclass_fields__)  # type: ignore[attr-defined]
        servers = []
        for item in data["servers"]:
            if isinstance(item, dict):
                servers.append(Config(**{k: v for k, v in item.items() if k in known}))
        try:
            interval = int(data.get("check_interval_sec", 4))
        except Exception:
            interval = 4
        return servers, max(2, interval)
    # v1形式 (単一サーバー)
    cfg = Config.load(path)
    return [cfg], max(2, int(cfg.check_interval_sec or 4))


def save_servers(path: Path, servers: list[Config], check_interval_sec: int = 4,
                 extra: dict | None = None) -> None:
    """v2形式で保存する。extra はアプリ全体設定 (例: auto_open_terminal) を同居させる"""
    data = {
        "version": CONFIG_VERSION,
        "check_interval_sec": int(check_interval_sec),
        "servers": [asdict(s) for s in servers],
    }
    if extra:
        data.update(extra)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_extra(path: Path) -> dict:
    """config.json のサーバー以外のトップレベル設定を読む (無ければ空)"""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {k: v for k, v in data.items()
                    if k not in ("servers", "version", "check_interval_sec")}
    except Exception:
        pass
    return {}


def find_server(servers: list[Config], key: str) -> Config | None:
    """名前 (部分一致・大文字小文字無視) または 1始まりの番号でサーバーを探す"""
    if key.isdigit():
        idx = int(key) - 1
        if 0 <= idx < len(servers):
            return servers[idx]
        return None
    lowered = key.lower()
    for s in servers:
        if s.server_name.lower() == lowered:
            return s
    for s in servers:
        if lowered in s.server_name.lower():
            return s
    return None


# ---------------------------------------------------------------------------
# Wake on LAN
# ---------------------------------------------------------------------------

def parse_mac(mac: str) -> bytes:
    """AA:BB:CC:DD:EE:FF / AA-BB-... / AABBCCDDEEFF の全形式に対応"""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(cleaned) != 12:
        raise ValueError(f"MACアドレスの形式が不正です: {mac!r} (16進12桁必要)")
    return bytes.fromhex(cleaned)


def format_mac(mac: bytes) -> str:
    """MACアドレスの表記ゆれ (ハイフン区切り等) を AA:BB:CC:DD:EE:FF 形式に揃える"""
    return ":".join(f"{b:02X}" for b in mac)


def build_magic_packet(mac: bytes, wol_password: str = "") -> bytes:
    """マジックパケット = FF×6 + MAC×16 (+ 任意のSecureOnパスワード6バイト) = 102バイト"""
    if len(mac) != 6:
        raise ValueError("MACアドレスは6バイト必要です")
    packet = b"\xff" * 6 + mac * 16
    if wol_password:
        pw = bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", wol_password))
        if len(pw) != 6:
            raise ValueError("WoLパスワード(SecureOn)は6バイト(16進12桁)で指定してください")
        packet += pw
    return packet


def compute_broadcast(host: str) -> str | None:
    """IPv4アドレスから /24 のブロードキャストを推定する (一般的な家庭LAN前提)"""
    try:
        parts = socket.inet_aton(host)
    except OSError:
        return None  # ホスト名などは推定しない
    return ".".join(str(b) for b in parts[:3]) + ".255"


def send_wol(cfg: Config, log=print, repeats: int = 3) -> list[str]:
    """
    マジックパケットを送信する。送信先は複数候補に送るのが確実:
      設定/推定ブロードキャスト, 255.255.255.255, サーバーのIP自体
    戻り値: 実際に送信した宛先リスト
    """
    mac = parse_mac(cfg.mac_address)
    packet = build_magic_packet(mac, cfg.wol_password)

    targets: list[str] = []
    for cand in (cfg.broadcast_address, compute_broadcast(cfg.host), "255.255.255.255", cfg.host):
        if cand and cand not in targets:
            targets.append(cand)

    sent: list[str] = []
    # ブロードキャスト用とユニキャスト用でソケットを分ける
    # (SO_BROADCAST付きソケットは制限環境でユニキャストまで弾かれることがあるため)
    bcast = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bcast.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    uni = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for i in range(repeats):
            for target in targets:
                is_broadcast = target.endswith(".255") or target == "255.255.255.255"
                sock = bcast if is_broadcast else uni
                try:
                    sock.sendto(packet, (target, int(cfg.wol_port)))
                    if i == 0:
                        sent.append(f"{target}:{cfg.wol_port}")
                except OSError as e:
                    if i == 0:
                        log(f"  送信失敗 {target}: {e}")
            if i < repeats - 1:
                time.sleep(0.15)
    finally:
        bcast.close()
        uni.close()
    log(f"WoL送信: MAC {format_mac(mac)} → {', '.join(sent)} (×{repeats}回, {len(packet)}バイト)")
    return sent


# ---------------------------------------------------------------------------
# 状態判定
# ---------------------------------------------------------------------------

STATUS_OFFLINE = "offline"        # pingもSSHも応答なし = 停止中
STATUS_BOOTING = "booting"        # pingは通るがSSHはまだ = 起動中 (またはSSH停止)
STATUS_ONLINE = "online"          # SSHポート応答あり = 起動済み

STATUS_LABEL = {
    STATUS_OFFLINE: ("停止中", "#9e9e9e"),
    STATUS_BOOTING: ("起動中…", "#ef6c00"),
    STATUS_ONLINE: ("起動済み", "#2e7d32"),
    "checking": ("確認中…", "#616161"),
    "unknown": ("未設定", "#9e9e9e"),
}


def server_row_action(cfg: Config, status: str) -> str:
    """一覧行の電源ボタンで実行できる操作を返す"""
    if not cfg.is_configured:
        return "disabled"
    if status in (STATUS_BOOTING, STATUS_ONLINE):
        return "disabled" if cfg.is_monitor_only() else "off"
    return "on"


def ping_host(host: str, timeout_ms: int = 700) -> bool:
    """ping を送って応答があれば True。機器が起動しているかの一次判定に使う"""
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), host]
        kwargs = {}
        if IS_WINDOWS:
            kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=4, **kwargs)
        return r.returncode == 0
    except Exception:
        return False


def tcp_open(host: str, port: int, timeout: float = 1.2) -> bool:
    """host の port へ TCP 接続できれば True (そのポートが開いているか)"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_status(cfg: Config) -> str:
    """サーバーの状態を判定して返す: 起動済み / 起動中 / 停止中 / 不明"""
    if not cfg.host:
        return "unknown"
    port = cfg.check_port
    if port:
        if tcp_open(cfg.host, port):
            return STATUS_ONLINE
        if ping_host(cfg.host):
            return STATUS_BOOTING
        return STATUS_OFFLINE
    # ポート判定なし (監視のみ・ポート未指定): ping応答 = 起動済み とみなす。
    # SSHポートが開かない「起動中…」で止まる問題が監視のみでは起きないようにするため
    return STATUS_ONLINE if ping_host(cfg.host) else STATUS_OFFLINE


def check_statuses(cfgs: list[Config], max_workers: int = 16) -> list[str]:
    """複数サーバーの状態を同時確認し、入力順で結果を返す"""
    if not cfgs:
        return []
    from concurrent.futures import ThreadPoolExecutor
    workers = min(max(1, max_workers), len(cfgs))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(check_status, cfgs))


# ---------------------------------------------------------------------------
# ネットワーク解決 (IP ⇔ ホスト名 / IP → MAC / MAC → IP)
# ---------------------------------------------------------------------------
# 仕組みと限界:
#  - IP→ホスト名 / ホスト名→IP: OSの名前解決 (DNS / mDNS / NetBIOS) を使う
#  - IP→MAC: 同一サブネット内なら ARP で引ける。まず ping して ARPキャッシュを
#    作ってから `arp -a` (Windows) / `ip neigh` (Linux) を読む
#  - MAC→IP: プロトコル上に逆引きは無いので、ARPキャッシュ→無ければ
#    サブネットを ping スイープして ARPテーブルから MAC で探す
#  - ルーター越え (別サブネット) の MAC は引けない (ルーターのMACになるだけ)

_MAC_FIND_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
_IPV4_FIND_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def is_ipv4(s: str) -> bool:
    """文字列が IPv4 アドレスの形なら True"""
    try:
        socket.inet_aton(s)
        return "." in s and all(part.isdigit() for part in s.split("."))
    except OSError:
        return False


def classify_query(q: str) -> str:
    """入力が 'ip' / 'mac' / 'hostname' のどれかを判定する"""
    q = (q or "").strip()
    if is_ipv4(q):
        return "ip"
    if "." not in q:  # ドットを含むものはホスト名寄り (MACはドット区切りを使わない前提)
        try:
            parse_mac(q)
            return "mac"
        except ValueError:
            pass
    return "hostname"


def resolve_ip(hostname: str) -> str | None:
    """ホスト名 → IPv4アドレス (正引き)"""
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except OSError:
        pass
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return None


def resolve_hostname(ip: str) -> str | None:
    """IP → ホスト名 (逆引き: DNS /hosts /NetBIOS等、OSの解決に任せる)"""
    try:
        name, _aliases, _addrs = socket.gethostbyaddr(ip)
        return name or None
    except OSError:
        return None


def parse_arp_output(text: str) -> dict[str, str]:
    """
    arp / ip neigh の出力を {IP: MAC(AA:BB形式)} に変換する純粋関数。
    Windows `arp -a` と Linux `ip neigh` / `arp -a` の両形式に対応。
    """
    result: dict[str, str] = {}
    for line in text.splitlines():
        ipm = _IPV4_FIND_RE.search(line)
        macm = _MAC_FIND_RE.search(line)
        if ipm and macm:
            try:
                result[ipm.group(0)] = format_mac(parse_mac(macm.group(0)))
            except ValueError:
                continue
    # ブロードキャスト/マルチキャスト等の不要エントリを除く
    result.pop("255.255.255.255", None)
    return {ip: mac for ip, mac in result.items()
            if not ip.endswith(".255") and mac != "FF:FF:FF:FF:FF:FF"}


def get_arp_table() -> dict[str, str]:
    """現在のARPキャッシュを {IP: MAC} で返す"""
    texts: list[str] = []
    cmds = [["arp", "-a"]] if IS_WINDOWS else [["ip", "neigh", "show"], ["arp", "-a"]]
    for cmd in cmds:
        try:
            kwargs = {}
            if IS_WINDOWS:
                kwargs["creationflags"] = 0x08000000
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                               errors="replace", **kwargs)
            if r.stdout:
                texts.append(r.stdout)
                break
        except Exception:
            continue
    merged: dict[str, str] = {}
    for t in texts:
        merged.update(parse_arp_output(t))
    return merged


def get_mac_for_ip(ip: str, ping_first: bool = True) -> str | None:
    """IP → MAC。同一サブネット専用。ARPキャッシュに無ければ ping してから再確認"""
    table = get_arp_table()
    if ip in table:
        return table[ip]
    if ping_first:
        ping_host(ip, timeout_ms=600)
        table = get_arp_table()
        return table.get(ip)
    return None


def get_local_ip() -> str | None:
    """この端末のLAN側IP (デフォルト経路の送信元アドレス)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return None


def subnet_base(ip: str) -> str | None:
    """"192.0.2.10" → "192.0.2" (/24前提)"""
    if ip and is_ipv4(ip):
        return ip.rsplit(".", 1)[0]
    return None


def ping_sweep(base: str, log=print, max_workers: int = 64) -> dict[str, str]:
    """
    /24 サブネット (base.1 〜 base.254) に一斉 ping して ARP を作り、
    {IP: MAC} を返す。数秒かかる。
    """
    from concurrent.futures import ThreadPoolExecutor
    hosts = [f"{base}.{i}" for i in range(1, 255)]
    log(f"{base}.1 〜 {base}.254 をスキャンしています…")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(ex.map(lambda h: ping_host(h, timeout_ms=500), hosts))
    table = get_arp_table()
    found = {ip: mac for ip, mac in table.items() if ip.startswith(base + ".")}
    log(f"スキャン完了: {len(found)}台見つかりました")
    return found


def scan_subnet_devices(base: str, log=print) -> list[tuple[str, str, str]]:
    """サブネットをスキャンし、IP・MAC・ホスト名の行データを作る"""
    found = ping_sweep(base, log=log)
    ordered = sorted(found.items(),
                     key=lambda item: tuple(int(part) for part in item[0].split(".")))
    return [(ip, mac, resolve_hostname(ip) or "") for ip, mac in ordered]


def find_ip_for_mac(mac: str, log=print, allow_scan: bool = True,
                    base: str | None = None) -> str | None:
    """MAC → IP。ARPキャッシュ→ (必要なら) 自分のサブネットをスキャンして探す"""
    try:
        target = format_mac(parse_mac(mac))
    except ValueError:
        return None
    for ip, m in get_arp_table().items():
        if m == target:
            return ip
    if not allow_scan:
        return None
    base = base or subnet_base(get_local_ip() or "")
    if not base:
        log("サブネットを特定できなかったためスキャンできませんでした")
        return None
    found = ping_sweep(base, log=log)
    for ip, m in found.items():
        if m == target:
            return ip
    return None


def lookup_device(query: str, log=print, allow_scan: bool = True) -> dict:
    """
    IP / ホスト名 / MAC のどれを渡されても、引けるものを全部引いて返す。
    戻り値: {"query", "type", "ip", "hostname", "mac"}
    """
    kind = classify_query(query)
    info = {"query": query.strip(), "type": kind,
            "ip": None, "hostname": None, "mac": None}
    if kind == "ip":
        info["ip"] = query.strip()
        info["hostname"] = resolve_hostname(info["ip"])
        info["mac"] = get_mac_for_ip(info["ip"])
    elif kind == "hostname":
        info["hostname"] = query.strip()
        info["ip"] = resolve_ip(info["hostname"])
        if info["ip"]:
            canonical = resolve_hostname(info["ip"])
            if canonical:
                info["hostname"] = canonical
            info["mac"] = get_mac_for_ip(info["ip"])
    else:  # mac
        info["mac"] = format_mac(parse_mac(query))
        info["ip"] = find_ip_for_mac(info["mac"], log=log, allow_scan=allow_scan)
        if info["ip"]:
            info["hostname"] = resolve_hostname(info["ip"])
    return info


# ---------------------------------------------------------------------------
# SSH (電源OFF / 再起動 / 接続テスト)
# ---------------------------------------------------------------------------

class SshError(RuntimeError):
    pass


def _sudo_command(cfg: Config, action: str) -> tuple[str, str | None]:
    """
    Linux用: 実行コマンドと stdin に流すパスワードを返す。
    パスワードがある場合: sudo -S でパスワードを stdin から渡す (サーバー側設定変更不要)
    パスワードが無い場合: sudo -n (パスワードなしsudo設定が前提)
    """
    pw = cfg.ssh_password
    if pw:
        return f"sudo -S -p '' {action}", pw + "\n"
    return f"sudo -n {action}", None


def remote_command(cfg: Config, action: str) -> tuple[str, str | None]:
    """
    SSH経由で電源操作する際のリモートコマンドを OS 別に返す。
    - Linux   : sudo poweroff / sudo reboot
    - Windows : shutdown /s|/r /t 0 /f (sudoは無い。管理者ユーザーでSSHする前提)
    """
    if action not in ("poweroff", "reboot"):
        return action, None
    if cfg.is_windows:
        flag = "/s" if action == "poweroff" else "/r"
        return f"shutdown {flag} /t 0 /f", None
    return _sudo_command(cfg, action)


def _rpc_shutdown(cfg: Config, action: str, log) -> None:
    """
    Windows対象のRPC方式: 操作する側のWindows標準 shutdown.exe で
    `shutdown /m \\host /s|/r /t 0 /f` を実行する。対象側にソフト導入は不要だが、
    実行ユーザーと同じ管理者資格情報が対象側にも必要 (ワークグループの場合)。
    """
    if not IS_WINDOWS:
        raise SshError("RPC方式 (shutdownコマンド) は、このアプリをWindowsで"
                       "実行している場合のみ使えます。方式をSSHに変えてください。")
    flag = "/s" if action == "poweroff" else "/r"
    cmd = ["shutdown", "/m", f"\\\\{cfg.host}", flag, "/t", "0", "/f"]
    log(f"実行: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                       errors="replace",
                       creationflags=0x08000000)  # CREATE_NO_WINDOW
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    if r.returncode != 0:
        hint = ""
        low = out.lower()
        if "access is denied" in low or "アクセスが拒否" in out or r.returncode == 5:
            hint = ("資格情報が対象PCで管理者として認められていません。"
                    "同じユーザー名/パスワードの管理者アカウントを対象側にも作るか、"
                    "READMEのRPC方式の注意 (UACリモート制限) を確認してください。")
        elif "network path" in low or "ネットワーク パス" in out or r.returncode == 53:
            hint = ("対象PCに到達できません。対象側ファイアウォールで"
                    "「ファイルとプリンターの共有」を許可しているか確認してください。")
        raise SshError(f"shutdownコマンドが失敗しました (exit={r.returncode}): "
                       f"{out} {hint}".strip())


def ssh_exec(cfg: Config, action: str, log=print, timeout: int = 15) -> None:
    """
    action: 'poweroff' / 'reboot' / テスト用コマンド
    電源OFF時はサーバー側が接続を切るため、切断エラーは成功として扱うケースがある
    (呼び出し側で状態遷移を確認する設計)。
    Windows対象 + RPC方式の場合は SSH を使わず shutdown.exe で実行する。
    """
    if (action in ("poweroff", "reboot") and cfg.is_windows
            and cfg.windows_method == "rpc"):
        _rpc_shutdown(cfg, action, log)
        return
    try:
        import paramiko  # 遅延import: 無い環境では ssh.exe フォールバックへ
        _ssh_exec_paramiko(cfg, action, log, timeout, paramiko)
    except ImportError:
        log("paramiko が無いため ssh.exe (鍵認証) で代替します")
        _ssh_exec_native(cfg, action, log, timeout)


def _ssh_exec_paramiko(cfg, action, log, timeout, paramiko) -> None:
    """paramiko を使って SSH でコマンドを実行する内部実装"""
    cmd, stdin_data = remote_command(cfg, action)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs = dict(
            hostname=cfg.host, port=int(cfg.ssh_port), username=cfg.ssh_user,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            allow_agent=False, look_for_keys=False,
        )
        if cfg.ssh_key_file:
            connect_kwargs["key_filename"] = os.path.expandvars(
                os.path.expanduser(cfg.ssh_key_file))
        elif cfg.ssh_password:
            connect_kwargs["password"] = cfg.ssh_password
        else:
            # 鍵もパスワードも無い場合はエージェント/デフォルト鍵に賭ける
            connect_kwargs["allow_agent"] = True
            connect_kwargs["look_for_keys"] = True
        client.connect(**connect_kwargs)
    except Exception as e:
        raise SshError(f"SSH接続に失敗しました: {e}") from e

    try:
        log(f"SSH接続OK: {cfg.ssh_user}@{cfg.host}:{cfg.ssh_port}")
        log(f"実行: {cmd}")
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        if stdin_data:
            try:
                stdin.write(stdin_data)
                stdin.flush()
            except Exception:
                pass
        try:
            exit_code = stdout.channel.recv_exit_status()
        except Exception:
            # poweroff/reboot で接続が先に切れた場合はここに来る = 正常な兆候
            exit_code = 0
        err = ""
        try:
            err = stderr.read().decode("utf-8", "replace").strip()
        except Exception:
            pass
        # sudo パスワード違い等は stderr に出る (Linux時)
        if err and not cfg.is_windows and ("incorrect password" in err or "try again" in err
                    or "a password is required" in err):
            raise SshError(
                "sudo のパスワード認証に失敗しました。設定のSSHパスワードを確認するか、"
                "サーバー側でパスワードなしsudoを設定してください (README参照)。 "
                f"詳細: {err}")
        if exit_code not in (0, -1) and action in ("poweroff", "reboot"):
            raise SshError(f"コマンドが失敗しました (exit={exit_code}): {err}")
    finally:
        try:
            client.close()
        except Exception:
            pass


def _ssh_exec_native(cfg: Config, action: str, log, timeout: int) -> None:
    """Windows標準 ssh.exe フォールバック。Linuxは鍵認証 + sudo -n 前提。"""
    if action in ("poweroff", "reboot"):
        if cfg.is_windows:
            remote = remote_command(cfg, action)[0]
        else:
            remote = f"sudo -n {action}"
    else:
        remote = action
    cmd = ["ssh", "-p", str(cfg.ssh_port),
           "-o", "BatchMode=yes",
           "-o", f"ConnectTimeout={min(timeout, 10)}",
           "-o", "StrictHostKeyChecking=accept-new"]
    if cfg.ssh_key_file:
        cmd += ["-i", os.path.expandvars(os.path.expanduser(cfg.ssh_key_file))]
    cmd += [f"{cfg.ssh_user}@{cfg.host}", remote]
    kwargs = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = 0x08000000
    log(f"実行: {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10, **kwargs)
    except FileNotFoundError as e:
        raise SshError("ssh.exe が見つかりません。paramiko をインストールしてください: "
                       "pip install paramiko") from e
    except subprocess.TimeoutExpired:
        if action in ("poweroff", "reboot"):
            return  # 切断で固まるケースは成功扱い
        raise
    if r.returncode != 0 and action in ("poweroff", "reboot"):
        err = (r.stderr or "").strip()
        if "password is required" in err or "interactive authentication" in err:
            raise SshError("鍵認証/パスワードなしsudo が未設定のため実行できませんでした。"
                           "paramiko を入れる (pip install paramiko) か、READMEの"
                           "パスワードなしsudo設定を行ってください。")
        raise SshError(f"ssh.exe が失敗しました (exit={r.returncode}): {err}")


TEST_COMMAND = {
    "linux": "whoami; hostname; uptime -p",
    "windows": "whoami & hostname & ver",
}


def ssh_test(cfg: Config, log=print) -> str:
    """接続テスト。RPC方式のWindowsはポート445の到達確認で代替する"""
    if cfg.is_monitor_only():
        st = check_status(cfg)
        label = STATUS_LABEL.get(st, ("?", ""))[0]
        via = f"ポート{cfg.check_port}" if cfg.check_port else "ping"
        return f"監視のみ設定: 現在の状態は「{label}」です ({via} で判定)"
    if cfg.is_windows and cfg.windows_method == "rpc":
        if tcp_open(cfg.host, 445, timeout=3):
            return ("RPC方式: SMBポート(445)に到達できました。"
                    "実際の電源OFF可否は資格情報に依存します (README参照)")
        raise SshError("RPC方式: SMBポート(445)に到達できません。"
                       "対象PCの電源と「ファイルとプリンターの共有」の許可を確認してください。")
    test_cmd = TEST_COMMAND["windows" if cfg.is_windows else "linux"]
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(hostname=cfg.host, port=int(cfg.ssh_port), username=cfg.ssh_user,
                      timeout=10, allow_agent=False, look_for_keys=False)
        if cfg.ssh_key_file:
            kwargs["key_filename"] = os.path.expandvars(os.path.expanduser(cfg.ssh_key_file))
        elif cfg.ssh_password:
            kwargs["password"] = cfg.ssh_password
        else:
            kwargs["allow_agent"] = True
            kwargs["look_for_keys"] = True
        client.connect(**kwargs)
        try:
            _, out, err = client.exec_command(test_cmd, timeout=10)
            result = out.read().decode("utf-8", "replace").strip()
            if not result:
                result = err.read().decode("utf-8", "replace").strip()
            return result
        finally:
            client.close()
    except ImportError:
        _ssh_exec_native(cfg, test_cmd, log, 10)
        return "(ssh.exe で接続できました)"


# ---------------------------------------------------------------------------
# SSHターミナル (Windows Terminal / PowerShell / cmd) と公開鍵登録
# ---------------------------------------------------------------------------

def ssh_capable(cfg: Config) -> bool:
    """SSHターミナルを開ける対象か (RPC方式のWindowsと監視のみは対象外)"""
    return (bool(cfg.ssh_user) and not cfg.is_monitor_only()
            and not (cfg.is_windows and cfg.windows_method == "rpc"))


def ssh_cli_args(cfg: Config) -> list[str]:
    """ssh.exe の引数列 (対話ターミナル用)"""
    args = ["ssh", "-p", str(cfg.ssh_port)]
    if cfg.ssh_key_file:
        args += ["-i", os.path.expandvars(os.path.expanduser(cfg.ssh_key_file))]
    args.append(f"{cfg.ssh_user}@{cfg.host}")
    return args


def build_wt_args(cfgs: list[Config]) -> list[str]:
    """
    Windows Terminal の引数列。複数台は ';' 区切りで1ウィンドウにタブを並べる。
    例: wt new-tab --title A ssh ... ; new-tab --title B ssh ...
    """
    args: list[str] = ["wt.exe"]
    for i, cfg in enumerate(cfgs):
        if i > 0:
            args.append(";")
        args += ["new-tab", "--title", cfg.server_name] + ssh_cli_args(cfg)
    return args


def build_fallback_args(cfg: Config, shell: str) -> list[str]:
    """wt が無い場合のフォールバック (ターミナルを開いたままにする)"""
    ssh_str = subprocess.list2cmdline(ssh_cli_args(cfg))
    if shell == "powershell":
        return ["powershell.exe", "-NoExit", "-Command", ssh_str]
    return ["cmd.exe", "/k", ssh_str]


def terminal_targets(cfgs: list[Config], log=print) -> list[Config]:
    """与えられた一覧から、SSHターミナルを開けるサーバーだけを抜き出す"""
    ready = []
    for cfg in cfgs:
        if not ssh_capable(cfg):
            log(f"[{cfg.server_name}] SSH情報が無いためターミナルの対象外です "
                f"(RPC方式のWindowsはSSH接続できません)")
            continue
        ready.append(cfg)
    return ready


def launch_terminal(cfgs: list[Config], log=print) -> str:
    """
    選択サーバーへのSSHターミナルを開く。戻り値: 使った手段 ("wt"/"powershell"/"cmd")。
    パスワード認証の場合はターミナル側でパスワード入力が必要 (OpenSSHの仕様)。
    鍵認証ならそのままログインまで行く。
    """
    import shutil
    targets = terminal_targets(cfgs, log=log)
    if not targets:
        raise SshError("ターミナルを開けるサーバーがありません "
                       "(SSHユーザー未設定 / RPC方式は対象外)")
    if shutil.which("wt.exe") or shutil.which("wt"):
        args = build_wt_args(targets)
        log(f"Windows Terminal で開きます: {' '.join(args)}")
        subprocess.Popen(args)
        return "wt"
    # フォールバック: 台ごとに別ウィンドウ
    for shell in ("powershell", "cmd"):
        exe = "powershell.exe" if shell == "powershell" else "cmd.exe"
        if shutil.which(exe) or shutil.which(shell):
            for cfg in targets:
                args = build_fallback_args(cfg, shell)
                log(f"{shell} で開きます: {' '.join(args)}")
                kwargs = {}
                if IS_WINDOWS:
                    kwargs["creationflags"] = 0x00000010  # CREATE_NEW_CONSOLE
                subprocess.Popen(args, **kwargs)
            return shell
    raise SshError("Windows Terminal / PowerShell / cmd のいずれも見つかりませんでした")


# --- 公開鍵登録 (鍵認証化) -----------------------------------------------------

def key_already_present(authorized_keys_text: str, pubkey_line: str) -> bool:
    """authorized_keys の中に同じ鍵 (種類+本体) が既にあるか。コメント部は無視して比較"""
    parts = pubkey_line.split()
    if len(parts) < 2:
        return False
    fingerprint = parts[0] + " " + parts[1]
    for line in authorized_keys_text.splitlines():
        lp = line.strip().split()
        if len(lp) >= 2 and (lp[0] + " " + lp[1]) == fingerprint:
            return True
    return False


def find_or_create_keypair(log=print) -> tuple[Path, Path]:
    """
    ローカルのSSH鍵ペア (秘密鍵, 公開鍵) を返す。既存が無ければ
    ssh-keygen で ed25519 を新規作成する (パスフレーズなし)。
    """
    ssh_dir = Path.home() / ".ssh"
    for name in ("id_ed25519", "id_ecdsa", "id_rsa"):
        priv = ssh_dir / name
        if priv.exists() and (ssh_dir / (name + ".pub")).exists():
            return priv, ssh_dir / (name + ".pub")
    ssh_dir.mkdir(parents=True, exist_ok=True)
    priv = ssh_dir / "id_ed25519"
    pub = ssh_dir / "id_ed25519.pub"
    log(f"SSH鍵ペアが無いため新規作成します: {priv}")
    kwargs = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = 0x08000000
    r = subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(priv)],
                       capture_output=True, text=True, timeout=30, **kwargs)
    if r.returncode != 0 or not pub.exists():
        raise SshError(f"ssh-keygen に失敗しました: {(r.stderr or '').strip()}")
    return priv, pub


def _connect_kwargs(cfg: Config, timeout: int) -> dict:
    """paramiko の connect() に渡す引数 (鍵・パスワード周り) を組み立てる"""
    kwargs = dict(hostname=cfg.host, port=int(cfg.ssh_port), username=cfg.ssh_user,
                  timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                  allow_agent=False, look_for_keys=False)
    if cfg.ssh_key_file:
        kwargs["key_filename"] = os.path.expandvars(os.path.expanduser(cfg.ssh_key_file))
    elif cfg.ssh_password:
        kwargs["password"] = cfg.ssh_password
    else:
        kwargs["allow_agent"] = True
        kwargs["look_for_keys"] = True
    return kwargs


def install_public_key(cfg: Config, log=print) -> tuple[str, bool]:
    """
    この端末の公開鍵を対象サーバーの authorized_keys に登録する (SFTPで追記)。
    戻り値: (秘密鍵パス, 新規登録したか)
    前提: パスワード認証で1回入れること。登録後はターミナルがノークリックになる。
    注意: Windows対象で管理者ユーザーの場合、OpenSSHは
      C:\\ProgramData\\ssh\\administrators_authorized_keys を参照するため、
      そちらへの登録が別途必要なことがある。
    """
    try:
        import paramiko
    except ImportError as e:
        raise SshError("paramiko が必要です: pip install paramiko") from e
    priv, pub = find_or_create_keypair(log=log)
    pubkey_line = pub.read_text(encoding="utf-8").strip()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(**_connect_kwargs(cfg, timeout=12))
    except Exception as e:
        raise SshError(f"SSH接続に失敗しました (パスワードを確認してください): {e}") from e
    try:
        sftp = client.open_sftp()
        try:
            # ホーム相対の .ssh を用意 (Linux/Windows OpenSSH どちらもホームが基準)
            try:
                sftp.mkdir(".ssh")
            except Exception:
                pass
            existing = ""
            try:
                with sftp.open(".ssh/authorized_keys", "r") as f:
                    existing = f.read().decode("utf-8", "replace")
            except IOError:
                existing = ""
            if key_already_present(existing, pubkey_line):
                log("公開鍵は既に登録済みでした")
                return str(priv), False
            with sftp.open(".ssh/authorized_keys", "a") as f:
                if existing and not existing.endswith("\n"):
                    f.write("\n")
                f.write(pubkey_line + "\n")
            if not cfg.is_windows:
                try:
                    sftp.chmod(".ssh", 0o700)
                except Exception:
                    pass
                try:
                    sftp.chmod(".ssh/authorized_keys", 0o600)
                except Exception:
                    pass
            log(f"公開鍵を登録しました: {pub.name} → {cfg.ssh_user}@{cfg.host}")
            return str(priv), True
        finally:
            sftp.close()
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 電源操作のオーケストレーション (GUI/CLI共通)
# ---------------------------------------------------------------------------

def power_on(cfg: Config, log=print, wait: bool = True, wait_timeout: int = 180) -> bool:
    """WoL送信 → (任意) SSH応答まで待つ。戻り値: 起動確認できたら True"""
    send_wol(cfg, log=log)
    if not wait:
        return True
    log("起動を待っています… (応答まで監視)")
    deadline = time.time() + wait_timeout
    while time.time() < deadline:
        if check_status(cfg) == STATUS_ONLINE:
            log(f"起動を確認しました")
            return True
        time.sleep(3)
    log(f"{wait_timeout}秒以内にSSH応答がありませんでした。"
        "パケットは送信済みなので、BIOS/UEFIとUbuntu側のWoL設定を確認してください (README参照)")
    return False


def power_off(cfg: Config, log=print, reboot: bool = False,
              wait: bool = True, wait_timeout: int = 90) -> bool:
    """SSH poweroff/reboot → (任意) 状態遷移を確認"""
    if cfg.is_monitor_only():
        raise SshError("監視のみ設定のサーバーは電源OFF/再起動できません "
                       "(SSH/RPCを使わない設定です)。物理スイッチ等で操作してください。")
    action = "reboot" if reboot else "poweroff"
    ssh_exec(cfg, action, log=log)
    log(f"{action} コマンドを送信しました")
    if not wait:
        return True
    if reboot:
        log("再起動を待っています… (一度落ちてからSSH応答が戻るまで監視)")
        deadline = time.time() + wait_timeout + 120
        went_down = False
        while time.time() < deadline:
            st = check_status(cfg)
            if st == STATUS_OFFLINE:
                went_down = True
            if went_down and st == STATUS_ONLINE:
                log("再起動を確認しました")
                return True
            time.sleep(3)
        log("再起動の完了を確認できませんでした。状態を確認してください")
        return False
    else:
        log("シャットダウンを待っています…")
        deadline = time.time() + wait_timeout
        while time.time() < deadline:
            if check_status(cfg) == STATUS_OFFLINE:
                log("シャットダウンを確認しました")
                return True
            time.sleep(3)
        log("まだ応答があります。もう少し待つか、状態を確認してください")
        return False


# ---------------------------------------------------------------------------
# GUI (Tkinter)
# ---------------------------------------------------------------------------

def run_gui(servers: list[Config], cfg_path: Path, check_interval_sec: int = 4) -> None:
    """GUI を組み立てて起動する (メインウィンドウ・一覧・ボタン・ログ)"""
    import tkinter as tk
    from tkinter import messagebox, scrolledtext, filedialog, ttk

    try:
        import paramiko  # noqa: F401
        has_paramiko = True
    except ImportError:
        has_paramiko = False

    root = tk.Tk()
    root.title(f"{APP_NAME} - サーバー一覧")
    if IS_WINDOWS:
        root.iconbitmap(default=str(resource_path("assets/wakedeck.ico")))
    else:
        icon_image = tk.PhotoImage(file=str(resource_path("assets/wakedeck.png")))
        root.iconphoto(True, icon_image)
    root.geometry("780x720")
    root.minsize(680, 620)

    interval = {"sec": max(2, int(check_interval_sec or 4))}
    extra = load_extra(cfg_path)
    auto_open_var = tk.BooleanVar(value=bool(extra.get("auto_open_terminal", False)))
    pending_terminal: set[int] = set()
    uid_counter = {"n": 0}
    uid_of: dict[int, Config] = {}       # uid -> Config
    cfg_to_uid: dict[int, int] = {}      # id(Config) -> uid (逆引きの高速化)
    status_of: dict[int, str] = {}       # uid -> status key
    busy: set[int] = set()
    log_queue: deque[str] = deque()
    ui_queue: queue.Queue[Callable[[], None]] = queue.Queue()
    polling: set[int] = set()
    status_refresh_pending = {"value": False}

    def next_uid(cfg: Config) -> int:
        """一覧の行に付ける連番の内部IDを新しく発行する"""
        uid_counter["n"] += 1
        uid = uid_counter["n"]
        uid_of[uid] = cfg
        cfg_to_uid[id(cfg)] = uid
        status_of[uid] = "checking" if cfg.is_configured else "unknown"
        return uid

    def uid_for_cfg(cfg: Config) -> int | None:
        """Config オブジェクトから一覧の UID を高速に探す"""
        return cfg_to_uid.get(id(cfg))

    for s in servers:
        next_uid(s)

    def persist():
        """現在のサーバー一覧と全体設定を config.json へ保存する"""
        extra["auto_open_terminal"] = bool(auto_open_var.get())
        save_servers(cfg_path, servers, interval["sec"], extra=extra)

    # --- ヘッダー -------------------------------------------------------------
    header = tk.Frame(root, padx=16, pady=10)
    header.pack(fill="x")
    tk.Label(header, text="サーバー一覧", font=("Yu Gothic UI", 16, "bold"),
             anchor="w").pack(side="left")
    summary_var = tk.StringVar(value="")
    tk.Label(header, textvariable=summary_var, font=("Yu Gothic UI", 10),
             fg="#555555").pack(side="left", padx=12)

    def refresh_summary():
        """上部の台数サマリ (全N台 起動済みX / 起動中Y / 停止中Z) を更新する"""
        counts = {"online": 0, "booting": 0, "offline": 0}
        for st in status_of.values():
            if st in counts:
                counts[st] += 1
        summary_var.set(f"全{len(servers)}台  起動済み {counts['online']} / "
                        f"起動中 {counts['booting']} / 停止中 {counts['offline']}")

    # --- 一覧 (Treeview) --------------------------------------------------------
    list_frame = tk.Frame(root, padx=16)
    list_frame.pack(fill="both", expand=False)
    columns = ("start", "name", "os", "host", "mac", "user", "status")
    tree = ttk.Treeview(list_frame, columns=columns, show="headings",
                        selectmode="extended", height=9)
    for col, title, width in (("name", "名前", 140), ("os", "OS", 64),
                              ("host", "IP / ホスト名", 125),
                              ("mac", "MACアドレス", 135), ("user", "SSHユーザー", 90),
                              ("status", "状態", 110)):
        tree.heading(col, text=title)
        tree.column(col, width=width, anchor="w")
    tree.heading("start", text="電源操作")
    tree.column("start", width=76, minwidth=76, stretch=False, anchor="center")
    tree.tag_configure("online", foreground="#2e7d32")
    tree.tag_configure("booting", foreground="#ef6c00")
    tree.tag_configure("offline", foreground="#9e9e9e")
    tree.tag_configure("checking", foreground="#616161")
    tree.tag_configure("unknown", foreground="#9e9e9e")
    tree.pack(side="left", fill="both", expand=True)
    start_buttons: dict[int, tk.Button] = {}
    button_sync_pending = {"value": False}

    def sync_start_buttons():
        button_sync_pending["value"] = False
        for uid, button in start_buttons.items():
            item = str(uid)
            box = tree.bbox(item, "start") if tree.exists(item) else ()
            if box:
                x, y, width, height = box
                button.place(x=x + (width - 44) // 2, y=y + 1,
                             width=44, height=max(1, height - 2))
            else:
                button.place_forget()

    def schedule_start_button_sync():
        if not button_sync_pending["value"]:
            button_sync_pending["value"] = True
            root.after_idle(sync_start_buttons)

    def scroll_tree(*args):
        tree.yview(*args)
        schedule_start_button_sync()

    scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=scroll_tree)

    def update_scrollbar(first, last):
        scrollbar.set(first, last)
        schedule_start_button_sync()

    tree.configure(yscrollcommand=update_scrollbar)
    scrollbar.pack(side="right", fill="y")

    def on_tree_configure(event):
        if event.widget is tree:
            schedule_start_button_sync()

    tree.bind("<Configure>", on_tree_configure, add="+")

    def status_text(uid: int) -> str:
        """状態キー (online など) から、表示用の文字列と色を返す"""
        if uid in busy:
            return "処理中…"
        label = STATUS_LABEL.get(status_of.get(uid, "unknown"), ("?", ""))[0]
        return f"● {label}"

    def row_values(uid: int) -> tuple:
        """一覧表の1行に表示する値の並びを作る"""
        cfg = uid_of[uid]
        user_disp = ("(監視のみ)" if cfg.is_monitor_only() else
                     cfg.ssh_user or ("(RPC方式)" if cfg.is_windows
                                      and cfg.windows_method == "rpc" else "(未設定)"))
        return ("", cfg.server_name, "Windows" if cfg.is_windows else "Linux",
                cfg.host, cfg.mac_address or "(未設定)",
                user_disp, status_text(uid))

    def update_start_button(uid: int):
        button = start_buttons.get(uid)
        cfg = uid_of.get(uid)
        if button is None or cfg is None:
            return
        action = server_row_action(cfg, status_of.get(uid, "unknown"))
        if uid in busy:
            button.configure(text="…", state="disabled")
        else:
            labels = {"on": "ON", "off": "OFF", "disabled": "—"}
            button.configure(text=labels[action],
                             state="disabled" if action == "disabled" else "normal")

    def add_row(uid: int):
        """一覧へサーバーの行を追加する"""
        cfg = uid_of[uid]
        tree.insert("", "end", iid=str(uid), values=row_values(uid),
                    tags=(status_of.get(uid, "unknown"),))
        button = tk.Button(
            tree, text="ON", width=4, font=("Yu Gothic UI", 8, "bold"),
            padx=2, pady=0, command=lambda row_uid=uid: toggle_server_power(row_uid),
            bg="#e8f5e9", fg="#2e7d32", activebackground="#c8e6c9",
            activeforeground="#1b5e20")
        start_buttons[uid] = button
        update_start_button(uid)
        schedule_start_button_sync()

    def update_row(uid: int):
        """一覧の既存の行の表示を最新状態に直す"""
        if tree.exists(str(uid)):
            tree.item(str(uid), values=row_values(uid),
                      tags=(status_of.get(uid, "unknown"),))
        update_start_button(uid)
        schedule_start_button_sync()

    for uid in list(uid_of.keys()):
        add_row(uid)
    refresh_summary()

    def selected_uids() -> list[int]:
        """一覧で選択中の行の内部IDリストを返す"""
        return [int(i) for i in tree.selection()]

    def selected_configs() -> list[Config]:
        """一覧で選択中のサーバーの設定リストを返す"""
        return [uid_of[u] for u in selected_uids() if u in uid_of]

    # --- ログ -------------------------------------------------------------------
    def log(msg: str, cfg: Config | None = None) -> None:
        """ログ欄へメッセージを追加する (別スレッドからもキュー経由で安全に追加できる)"""
        prefix = f"[{cfg.server_name}] " if cfg is not None else ""
        log_queue.append(f"[{time.strftime('%H:%M:%S')}] {prefix}{msg}")

    def post_to_ui(callback: Callable[[], None]) -> None:
        ui_queue.put(callback)

    def pump_ui_queue():
        root.after(40, pump_ui_queue)
        while True:
            try:
                callback = ui_queue.get_nowait()
            except queue.Empty:
                return
            callback()

    def pump_log():
        """ログキューに溜まった分を画面へ反映する (定期的に呼ばれる)"""
        lines = []
        while log_queue:
            lines.append(log_queue.popleft())
        if lines:
            log_text.configure(state="normal")
            log_text.insert("end", "\n".join(lines) + "\n")
            line_count = int(log_text.index("end-1c").split(".")[0])
            if line_count > 2000:
                log_text.delete("1.0", f"{line_count - 2000}.0")
            log_text.see("end")
            log_text.configure(state="disabled")
        root.after(120, pump_log)

    # --- 状態ポーリング -----------------------------------------------------------
    def refresh_status_views():
        """状態サマリとボタンの再計算をまとめて実行する"""
        status_refresh_pending["value"] = False
        refresh_summary()
        update_buttons()

    def set_status(uid: int, st: str):
        """サーバーの状態を記録し、一覧の行とサマリへ反映する"""
        status_of[uid] = st
        update_row(uid)
        if not status_refresh_pending["value"]:
            status_refresh_pending["value"] = True
            root.after_idle(refresh_status_views)

    def poll_uid(uid: int):
        """1台分の状態確認を裏で実行する"""
        cfg = uid_of.get(uid)
        if cfg is None or uid in polling:
            return
        polling.add(uid)

        def worker():
            """画面を固まらせないよう、時間のかかる処理を別スレッドで実行する本体"""
            try:
                st = check_status(cfg) if cfg.is_configured else "unknown"
            except Exception as e:
                st = "unknown"
                log(f"状態確認に失敗しました: {e}", cfg)

            def finish():
                polling.discard(uid)
                if uid in uid_of:
                    set_status(uid, st)
            post_to_ui(finish)

        threading.Thread(target=worker, daemon=True).start()

    def poll_all():
        """全台分の状態確認を開始する"""
        for uid in list(uid_of.keys()):
            if uid not in busy:
                poll_uid(uid)
        root.after(interval["sec"] * 1000, poll_all)

    # --- 操作 ---------------------------------------------------------------------
    progress = None  # 下で作る。前方参照用
    log_label = None  # 同上 (プログレスバーを元の位置に戻すために使う)
    progress_shown = {"value": False}  # バーが表示中かどうか

    def refresh_progress():
        """起動確認中のプログレスバー表示を更新する (待機中はバー自体を隠す)"""
        if progress is None:
            return
        if busy:
            if not progress_shown["value"]:
                # ログ見出しの直前という元の位置に戻す (pack の順序を保つため)
                progress.pack(fill="x", padx=16, pady=(8, 0), before=log_label)
                progress_shown["value"] = True
            progress.start(12)
        else:
            progress.stop()
            if progress_shown["value"]:
                progress.pack_forget()
                progress_shown["value"] = False

    def run_op(cfg: Config, fn, name: str, kind: str = ""):
        """電源操作 (ON/OFF/再起動) を裏で実行し、終わったら画面へ反映する共通処理"""
        uid = uid_for_cfg(cfg)
        if uid is None or uid in busy:
            return
        busy.add(uid)
        update_row(uid)
        update_buttons()
        refresh_progress()

        def worker():
            """画面を固まらせないよう、時間のかかる処理を別スレッドで実行する本体"""
            ok = False
            error = None
            try:
                ok = fn(cfg, log=lambda m: log(m, cfg))
                log(f"--- {name} {'完了' if ok else '要確認'} ---", cfg)
            except Exception as exc:
                error = str(exc)
                log(f"エラー: {error}", cfg)
            finally:
                def finish():
                    """電源操作が終わった後の後処理 (状態の再確認や、自動ターミナルの取りまとめ)"""
                    busy.discard(uid)
                    if error is not None:
                        messagebox.showerror(
                            APP_NAME, f"[{cfg.server_name}] {error}")
                    update_row(uid)
                    refresh_progress()
                    update_buttons()
                    poll_uid(uid)
                    # 電源ON成功 + 設定ONなら、溜まった分をまとめてターミナルで開く
                    if kind == "on" and ok and auto_open_var.get() and ssh_capable(cfg):
                        pending_terminal.add(uid)
                    if not busy and pending_terminal:
                        cfgs = [uid_of[u] for u in pending_terminal if u in uid_of]
                        pending_terminal.clear()
                        if cfgs:
                            try:
                                launch_terminal(cfgs, log=lambda m: log(m))
                            except Exception as e:
                                log(f"ターミナルを開けませんでした: {e}")
                post_to_ui(finish)
        threading.Thread(target=worker, daemon=True).start()

    def targets_for(action: str) -> list[Config]:
        """操作対象を選別する。未設定・対象外の台は理由をログに出して外す"""
        cfgs = selected_configs()
        if not cfgs:
            messagebox.showinfo(APP_NAME, "一覧からサーバーを選択してください。\n"
                                          "Ctrl/Shift+クリックで複数選択できます。")
            return []
        ready = []
        for c in cfgs:
            uid = uid_for_cfg(c)
            st = status_of.get(uid, "unknown") if uid is not None else "unknown"
            if not c.is_configured:
                log("未設定のためスキップしました (ダブルクリックで編集)", c)
                continue
            if action in ("off", "reboot") and c.is_monitor_only():
                log("監視のみ設定のため電源OFF/再起動はできません (WoLと状態表示のみ)", c)
                continue
            if action == "on" and st == STATUS_ONLINE:
                log("既に起動済みのためスキップしました", c)
                continue
            if action in ("off", "reboot") and st == STATUS_OFFLINE:
                log("停止中のためスキップしました", c)
                continue
            ready.append(c)
        return ready

    def start_server(uid: int):
        """指定した1台の電源ON処理を開始する"""
        cfg = uid_of.get(uid)
        if cfg is None or uid in busy:
            return
        if not cfg.is_configured:
            log("未設定のため起動できません (ダブルクリックで編集)", cfg)
            return
        if status_of.get(uid) == STATUS_ONLINE:
            log("既に起動済みのためスキップしました", cfg)
            return
        log("--- 電源ON ---", cfg)
        run_op(cfg, lambda target, log: power_on(target, log=log),
               "電源ON", kind="on")

    def do_on(cfgs: list[Config] | None = None):
        """「電源を入れる」ボタンの処理"""
        for c in (cfgs if cfgs is not None else targets_for("on")):
            uid = uid_for_cfg(c)
            if uid is not None:
                start_server(uid)

    def do_off(cfgs: list[Config] | None = None, reboot: bool = False):
        """「電源を切る / 再起動」ボタンの処理"""
        targets = cfgs if cfgs is not None else targets_for("reboot" if reboot else "off")
        if not targets:
            return
        verb = "再起動" if reboot else "シャットダウン"
        names = "\n".join(f"・{c.server_name} ({c.host})" for c in targets)
        if not messagebox.askyesno(APP_NAME, f"以下を{verb}しますか？\n\n{names}"):
            return
        for c in targets:
            log(f"--- {'再起動' if reboot else '電源OFF'} ---", c)
            run_op(c, lambda cfg, log, r=reboot: power_off(cfg, log=log, reboot=r),
                   "再起動" if reboot else "電源OFF")

    def toggle_server_power(uid: int):
        """一覧行のボタンから、状態に応じて起動またはシャットダウンする"""
        cfg = uid_of.get(uid)
        if cfg is None or uid in busy:
            return
        action = server_row_action(cfg, status_of.get(uid, "unknown"))
        if action == "off":
            do_off([cfg])
        elif action == "on":
            start_server(uid)

    def do_all_on():
        """「すべてON」ボタンの処理"""
        do_on([c for c in servers
               if c.is_configured and status_of.get(uid_for_cfg(c), "unknown") != STATUS_ONLINE])

    def do_all_off():
        """「すべてOFF」ボタンの処理"""
        do_off([c for c in servers
                if c.is_configured and not c.is_monitor_only()
                and status_of.get(uid_for_cfg(c), "unknown") != STATUS_OFFLINE])

    # --- ボタン -------------------------------------------------------------------
    btn_frame = tk.Frame(root, padx=16, pady=8)
    btn_frame.pack(fill="x")
    btn_on = tk.Button(btn_frame, text="⏻ 電源を入れる", font=("Yu Gothic UI", 12, "bold"),
                       bg="#2e7d32", fg="white", activebackground="#1b5e20",
                       activeforeground="white", width=14, command=lambda: do_on())
    btn_off = tk.Button(btn_frame, text="⏻ 電源を切る", font=("Yu Gothic UI", 12, "bold"),
                        bg="#c62828", fg="white", activebackground="#8e0000",
                        activeforeground="white", width=14, command=lambda: do_off())
    btn_reboot = tk.Button(btn_frame, text="再起動", font=("Yu Gothic UI", 11),
                           width=10, command=lambda: do_off(reboot=True))
    btn_terminal = tk.Button(btn_frame, text="ターミナル", font=("Yu Gothic UI", 11, "bold"),
                             width=11, command=lambda: do_terminal())
    btn_on.pack(side="left", padx=(0, 6))
    btn_off.pack(side="left", padx=6)
    btn_reboot.pack(side="left", padx=6)
    btn_terminal.pack(side="left", padx=6)
    # すべてON/OFF は opt_frame 側に置く (btn_frame はターミナル追加で幅が一杯のため)

    mgmt = tk.Frame(root, padx=16)
    mgmt.pack(fill="x")
    tk.Button(mgmt, text="＋ サーバー追加", command=lambda: edit_server(None)).pack(side="left", padx=(0, 6))
    tk.Button(mgmt, text="編集", command=lambda: edit_selected()).pack(side="left", padx=6)
    tk.Button(mgmt, text="複製", command=lambda: duplicate_selected()).pack(side="left", padx=6)
    tk.Button(mgmt, text="削除", command=lambda: delete_selected()).pack(side="left", padx=6)
    tk.Button(mgmt, text="状態を更新", command=lambda: [poll_uid(u) for u in uid_of]).pack(side="right")
    tk.Button(mgmt, text="🔍 IP/ホスト名/MAC検索", command=lambda: open_lookup_dialog()).pack(side="right", padx=6)

    opt_frame = tk.Frame(root, padx=16)
    opt_frame.pack(fill="x")
    tk.Checkbutton(opt_frame, text="電源ONで起動したら自動でターミナルも開く (SSH可能な台のみ)",
                   variable=auto_open_var, command=persist,
                   font=("Yu Gothic UI", 9)).pack(side="left")
    tk.Button(opt_frame, text="すべてON", font=("Yu Gothic UI", 11),
              command=do_all_on).pack(side="right", padx=(6, 0))
    tk.Button(opt_frame, text="すべてOFF", font=("Yu Gothic UI", 11),
              command=do_all_off).pack(side="right", padx=6)

    def do_terminal():
        """「ターミナル」ボタンの処理。選択中の開ける台をまとめて開く"""
        cfgs = [c for c in selected_configs() if ssh_capable(c)]
        if not cfgs:
            messagebox.showinfo(APP_NAME, "SSHターミナルを開けるサーバーが選択されていません。\n"
                                          "(SSHユーザー未設定 / RPC方式のWindowsは対象外)")
            return
        try:
            method = launch_terminal(cfgs, log=lambda m: log(m))
            log(f"ターミナルを開きました ({method}): "
                + ", ".join(c.server_name for c in cfgs))
        except Exception as e:
            log(f"ターミナルを開けませんでした: {e}")
            messagebox.showerror(APP_NAME, str(e))

    def update_buttons():
        """選択状態と各台の状態に応じて、ボタンの有効/無効を切り替える"""
        has_sel = bool(tree.selection())
        selected = selected_configs()
        any_free = False
        term_ready = False
        for c in selected:
            uid = uid_for_cfg(c)
            if uid is None:
                continue
            if uid not in busy:
                any_free = True
            if ssh_capable(c) and status_of.get(uid, "unknown") == STATUS_ONLINE and uid not in busy:
                term_ready = True
        state = "normal" if (has_sel and any_free) else "disabled"
        btn_on.configure(state=state)
        btn_off.configure(state=state)
        btn_reboot.configure(state=state)
        btn_terminal.configure(state="normal" if term_ready else "disabled")

    tree.bind("<<TreeviewSelect>>", lambda e: update_buttons())
    tree.bind("<Double-1>", lambda e: edit_selected())

    def clear_selection_on_blank_click(event):
        """一覧の行がない場所やウィンドウの余白をクリックしたら選択を解除する。
        ボタン等の操作部品の上でのクリックでは解除しない (誤操作防止)"""
        if event.widget.winfo_toplevel() is not root:
            return  # ダイアログ (別ウィンドウ) 上のクリックは対象外
        if event.widget is tree:
            # セル (行の中身) 以外 = 行がない場所・見出し・行の右端の余白など
            if tree.identify_region(event.x, event.y) != "cell":
                tree.selection_set(())
                update_buttons()
        elif event.widget is root or isinstance(
                event.widget, (tk.Frame, tk.Label, tk.Text, ttk.Scrollbar)):
            tree.selection_set(())
            update_buttons()

    root.bind_all("<Button-1>", clear_selection_on_blank_click, add="+")

    from tkinter import ttk as _ttk  # progress用 (ttkはimport済みだが明示)
    progress = _ttk.Progressbar(root, mode="indeterminate")
    progress.pack(fill="x", padx=16, pady=(8, 0))
    progress.pack_forget()  # 初期状態は待機中なので隠しておく (refresh_progress が必要時に出す)

    log_label = tk.Label(root, text="ログ", font=("Yu Gothic UI", 10, "bold"),
                         anchor="w")
    log_label.pack(fill="x", padx=16, pady=(10, 0))
    log_text = scrolledtext.ScrolledText(root, height=11, font=("Consolas", 9),
                                         state="disabled", wrap="word")
    log_text.pack(fill="both", expand=True, padx=16, pady=(2, 8))

    footer = tk.Frame(root, padx=16, pady=8)
    footer.pack(fill="x")
    if not has_paramiko:
        tk.Label(footer, text="⚠ paramiko未導入: 鍵認証のみ対応 (pip install paramiko 推奨)",
                 fg="#c62828", font=("Yu Gothic UI", 8)).pack(side="left")
    tk.Label(footer, text=f"v{APP_VERSION}  /  設定: {cfg_path.name}",
             fg="#999999", font=("Yu Gothic UI", 8)).pack(side="right")

    # --- サーバー追加/編集ダイアログ ------------------------------------------------
    def edit_selected():
        """「編集」ボタンの処理"""
        sel = selected_uids()
        if len(sel) != 1:
            if sel:
                messagebox.showinfo(APP_NAME, "編集は1台だけ選択してください。")
            return
        edit_server(uid_of[sel[0]])

    def duplicate_selected():
        """「複製」ボタンの処理"""
        sel = selected_uids()
        if len(sel) != 1:
            return
        src = uid_of[sel[0]]
        import copy as _copy
        dup = _copy.deepcopy(src)
        dup.server_name = src.server_name + " (コピー)"
        servers.append(dup)
        uid = next_uid(dup)
        add_row(uid)
        persist()
        refresh_summary()
        log(f"複製しました: {src.server_name} → {dup.server_name}")
        edit_server(dup)

    def delete_selected():
        """「削除」ボタンの処理"""
        sel = selected_uids()
        if not sel:
            return
        names = ", ".join(uid_of[u].server_name for u in sel)
        if not messagebox.askyesno(APP_NAME, f"以下を一覧から削除しますか？\n{names}\n"
                                             "(サーバー本体には影響しません)"):
            return
        for uid in sel:
            cfg = uid_of.pop(uid)
            cfg_to_uid.pop(id(cfg), None)
            status_of.pop(uid, None)
            servers.remove(cfg)
            button = start_buttons.pop(uid, None)
            if button is not None:
                button.destroy()
            if tree.exists(str(uid)):
                tree.delete(str(uid))
        schedule_start_button_sync()
        persist()
        refresh_summary()
        update_buttons()
        log(f"削除しました: {names}")

    def open_lookup_dialog():
        """IP / ホスト名 / MAC 検索ダイアログを開く"""
        from concurrent.futures import ThreadPoolExecutor

        win = tk.Toplevel(root)
        win.title("ネットワーク検索 (IP / ホスト名 / MAC)")
        win.geometry("660x580")
        state = {"info": None}
        scan_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="WakeDeck-scan")

        def close_lookup_dialog():
            scan_executor.shutdown(wait=False, cancel_futures=True)
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", close_lookup_dialog)

        tk.Label(win, text="IPアドレス / ホスト名 / MACアドレス のどれを入れても検索できます",
                 font=("Yu Gothic UI", 10, "bold"), anchor="w").pack(fill="x", padx=14, pady=(12, 2))
        tk.Label(win, text="IP→MAC は同一サブネット内のみ (ARP)。MAC→IP はARPに無い場合、"
                           "自分のサブネットを自動スキャンします (数秒かかります)",
                 font=("Yu Gothic UI", 8), fg="#666666", anchor="w").pack(fill="x", padx=14)
        top = tk.Frame(win, padx=14, pady=8)
        top.pack(fill="x")
        entry = tk.Entry(top, font=("Consolas", 12))
        entry.pack(side="left", fill="x", expand=True)
        entry.focus_set()
        result_var = tk.StringVar(value="")
        status_var = tk.StringVar(value="")
        add_btn = tk.Button(win, text="この情報でサーバー追加", state="disabled")
        scan_add_btn = tk.Button(win, text="選択した機器をサーバー追加", state="disabled")
        lookup_active = {"value": False}

        def show_info(info):
            """検索結果をダイアログへ表示する"""
            state["info"] = info
            registered = ""
            if info.get("ip"):
                hit = next((s for s in servers if s.host == info["ip"]), None)
                if hit:
                    registered = f"\n登録済みサーバー: {hit.server_name}"
            result_var.set(
                f"IPアドレス : {info.get('ip') or '(取得できませんでした)'}\n"
                f"ホスト名   : {info.get('hostname') or '(取得できませんでした)'}\n"
                f"MACアドレス: {info.get('mac') or '(取得できませんでした)'}{registered}")
            add_btn.configure(state="normal" if (info.get("ip") or info.get("mac")) else "disabled")
            log(f"検索 [{info['query']}]: IP={info.get('ip')} / "
                f"ホスト名={info.get('hostname')} / MAC={info.get('mac')}")

        def do_lookup():
            """検索ボタン: 入力された IP / ホスト名 / MAC を解決する"""
            q = entry.get().strip()
            if not q or lookup_active["value"]:
                return
            lookup_active["value"] = True
            status_var.set("検索中…")
            add_btn.configure(state="disabled")
            lookup_button.configure(state="disabled")

            def worker():
                error = None
                try:
                    info = lookup_device(
                        q, log=lambda message: post_to_ui(
                            lambda text=message: update_lookup_status(text)))
                except Exception as exc:
                    error = str(exc)
                    info = {"query": q, "type": "?", "ip": None, "hostname": None, "mac": None}
                    log(f"検索に失敗しました: {error}")
                post_to_ui(lambda result=info, detail=error: finish_lookup(result, detail))

            def update_lookup_status(message: str):
                if win.winfo_exists():
                    status_var.set(message)

            def finish_lookup(info: dict, error: str | None):
                if not win.winfo_exists():
                    return
                lookup_active["value"] = False
                lookup_button.configure(state="normal")
                show_info(info)
                status_var.set(f"検索に失敗しました: {error}" if error else "")

            threading.Thread(target=worker, daemon=True).start()

        lookup_button = tk.Button(top, text="検索", font=("Yu Gothic UI", 11, "bold"),
                                  width=8, command=do_lookup)
        lookup_button.pack(side="left", padx=(8, 0))
        entry.bind("<Return>", lambda e: do_lookup())
        tk.Label(win, textvariable=result_var, font=("Consolas", 11), justify="left",
                 anchor="w").pack(fill="x", padx=14, pady=4)
        add_btn.pack(anchor="w", padx=14)

        def add_from_info():
            """検索結果をそのままサーバーとして追加する"""
            info = state["info"]
            if not info:
                return
            pre = Config(server_name=info.get("hostname") or info.get("ip") or "新規サーバー",
                         host=info.get("ip") or "",
                         mac_address=info.get("mac") or "")
            close_lookup_dialog()
            edit_server(None, prefill=pre)
        add_btn.configure(command=add_from_info)

        ttk.Separator(win).pack(fill="x", padx=14, pady=10)
        scan_top = tk.Frame(win, padx=14)
        scan_top.pack(fill="x")
        tk.Label(scan_top, text="LAN内スキャン", font=("Yu Gothic UI", 10, "bold")).pack(side="left")
        scan_tree = ttk.Treeview(win, columns=("ip", "mac", "host", "reg"),
                                 show="headings", height=8, selectmode="browse")
        for col, title, w in (("ip", "IPアドレス", 130), ("mac", "MACアドレス", 150),
                              ("host", "ホスト名", 200), ("reg", "登録", 70)):
            scan_tree.heading(col, text=title)
            scan_tree.column(col, width=w, anchor="w")
        scan_tree.pack(fill="both", expand=True, padx=14, pady=6)

        def do_scan():
            """LANスキャンを実行して、同一サブネットの機器を一覧にする"""
            status_var.set("スキャン中…")
            scan_button.configure(state="disabled")
            scan_add_btn.configure(state="disabled")
            for iid in scan_tree.get_children():
                scan_tree.delete(iid)

            fallback_host = servers[0].host if servers else ""

            def perform_scan() -> list[tuple[str, str, str]]:
                base = subnet_base(get_local_ip() or "") or subnet_base(fallback_host)
                if not base:
                    raise ValueError("サブネットを特定できませんでした")
                return scan_subnet_devices(base, log=lambda _: None)

            future = scan_executor.submit(perform_scan)

            def finish_scan():
                """完了したスキャン結果だけをUIスレッドで反映する"""
                if not win.winfo_exists():
                    return
                if not future.done():
                    win.after(100, finish_scan)
                    return

                scan_button.configure(state="normal")
                error = future.exception()
                if error is not None:
                    message = f"スキャンに失敗しました: {error}"
                    status_var.set(message)
                    log(message)
                    return

                rows = future.result()
                registered_hosts = {server.host for server in servers}
                for ip, mac, name in rows:
                    reg = "済" if ip in registered_hosts else ""
                    scan_tree.insert("", "end", iid=ip,
                                     values=(ip, mac, name, reg))
                status_var.set(f"スキャン完了: {len(rows)}台")

            win.after(100, finish_scan)

        scan_button = tk.Button(scan_top, text="スキャン開始", command=do_scan)
        scan_button.pack(side="left", padx=10)
        tk.Label(win, textvariable=status_var, font=("Yu Gothic UI", 9),
                 fg="#555555", anchor="w").pack(fill="x", padx=14)
        scan_add_btn.pack(anchor="w", padx=14, pady=(0, 10))

        def on_scan_select(e=None):
            """スキャン結果の行を選んだときの処理"""
            scan_add_btn.configure(state="normal" if scan_tree.selection() else "disabled")

        def add_from_scan():
            """スキャン結果で選んだ機器をサーバーとして追加する"""
            sel = scan_tree.selection()
            if not sel:
                return
            ip = sel[0]
            vals = scan_tree.item(ip, "values")
            pre = Config(server_name=str(vals[2]) or ip, host=ip,
                         mac_address=str(vals[1]))
            close_lookup_dialog()
            edit_server(None, prefill=pre)
        scan_add_btn.configure(command=add_from_scan)
        scan_tree.bind("<<TreeviewSelect>>", on_scan_select)
        scan_tree.bind("<Double-1>", lambda e: add_from_scan())

    def edit_server(existing: Config | None, prefill: Config | None = None):
        """サーバーの追加/編集ダイアログを開く (cfg=None のときは新規追加)"""
        is_new = existing is None
        cfg = existing if existing is not None else (prefill if prefill is not None else Config())
        win = tk.Toplevel(root)
        win.title("サーバーを追加" if is_new else f"サーバーを編集 - {cfg.server_name}")
        # 高さは固定しない: 内容に合わせて自動で決める (固定760pxでは環境によって
        # 下部のボタンが見切れるため)。幅だけ最小値を指定する
        win.minsize(480, 0)
        win.grab_set()
        entries: dict = {}
        combo_values = {
            "os_type": ["Ubuntu / Linux", "Windows"],
            "windows_method": ["SSH (OpenSSHサーバー)", "RPC (shutdownコマンド)"],
        }
        fields = [
            ("server_name", "表示名", cfg.server_name, False),
            ("os_type", "OS種別",
             "Windows" if cfg.is_windows else "Ubuntu / Linux", "combo"),
            ("windows_method", "電源OFF方式 (Windows対象のみ)",
             "RPC (shutdownコマンド)" if cfg.windows_method == "rpc"
             else "SSH (OpenSSHサーバー)", "combo"),
            ("host", "対象のIP / ホスト名 *",
             cfg.host if (not is_new or prefill is not None) else "", False),
            ("mac_address", "MACアドレス * (例 AA:BB:CC:DD:EE:FF)", cfg.mac_address, False),
            ("broadcast_address", "ブロードキャスト (空=自動)", cfg.broadcast_address, False),
            ("wol_port", "WoLポート", str(cfg.wol_port), False),
            ("ssh_user", "SSHユーザー名 (RPC方式では不要)", cfg.ssh_user, False),
            ("ssh_port", "SSHポート", str(cfg.ssh_port), False),
            ("status_port", "状態確認用ポート (監視のみ用・任意 例:3389、空=pingのみ)",
             str(cfg.status_port or ""), False),
            ("ssh_password", "SSHパスワード (Linuxはsudoも兼用)", cfg.ssh_password, True),
            ("ssh_key_file", "秘密鍵ファイル (任意)", cfg.ssh_key_file, False),
        ]
        row = 0
        for key, label, value, is_pw in fields:
            tk.Label(win, text=label, font=("Yu Gothic UI", 9),
                     anchor="w").grid(row=row, column=0, sticky="w", padx=12,
                                      pady=(8, 0), columnspan=2)
            row += 1
            if is_pw == "combo":
                e = ttk.Combobox(win, values=combo_values[key], state="readonly",
                                 font=("Yu Gothic UI", 10))
                e.set(value)
            else:
                e = tk.Entry(win, font=("Consolas", 10), show="●" if is_pw else "")
                e.insert(0, value)
            e.grid(row=row, column=0, sticky="ew", padx=12, pady=(0, 2))
            if key == "ssh_key_file":
                def browse(entry=e):
                    """鍵ファイルの「参照」ボタン: ファイル選択ダイアログを開く"""
                    p = filedialog.askopenfilename(title="秘密鍵を選択")
                    if p:
                        entry.delete(0, "end")
                        entry.insert(0, p)
                tk.Button(win, text="参照", command=browse).grid(row=row, column=1, padx=(0, 12))
            entries[key] = e
            row += 1
        win.columnconfigure(0, weight=1)
        show_var = tk.BooleanVar(value=False)

        def toggle_show():
            """パスワード欄の表示 / 伏字を切り替える"""
            entries["ssh_password"].configure(show="" if show_var.get() else "●")
        tk.Checkbutton(win, text="パスワードを表示", variable=show_var,
                       command=toggle_show).grid(row=row, column=0, sticky="w", padx=12)
        row += 1

        tk.Label(win, text="パスワードはWindowsのDPAPIで暗号化して config.json に保存します。\n"
                           "MACアドレス: Linuxは `ip link`、Windowsは `ipconfig /all` で確認できます。\n"
                           "Windows対象の電源ONには、高速スタートアップOFF + NICのWoL設定が必要です (README参照)。",
                 fg="#666666", font=("Yu Gothic UI", 8), justify="left",
                 anchor="w").grid(row=row, column=0, sticky="w", padx=12, pady=6, columnspan=2)
        row += 1

        def collect(target: Config) -> bool:
            """ダイアログの入力欄の値を Config に移す。入力が不正なら警告して False を返す"""
            try:
                target.server_name = entries["server_name"].get().strip() or target.server_name
                target.host = entries["host"].get().strip()
                mac_raw = entries["mac_address"].get().strip()
                target.mac_address = format_mac(parse_mac(mac_raw)) if mac_raw else ""
                target.broadcast_address = entries["broadcast_address"].get().strip()
                target.wol_port = int(entries["wol_port"].get().strip() or 9)
                target.ssh_user = entries["ssh_user"].get().strip()
                target.ssh_port = int(entries["ssh_port"].get().strip() or 22)
                target.ssh_password = entries["ssh_password"].get()
                target.ssh_key_file = entries["ssh_key_file"].get().strip()
                target.os_type = ("windows" if entries["os_type"].get().startswith("Windows")
                                  else "linux")
                target.windows_method = ("rpc" if entries["windows_method"].get().startswith("RPC")
                                         else "ssh")
                target.status_port = int(entries["status_port"].get().strip() or 0)
                target.monitor_only = False  # 監視のみは SSHユーザー名の有無から自動判定する
                return True
            except Exception as e:
                messagebox.showerror("設定", str(e), parent=win)
                return False

        btns = tk.Frame(win)
        btns.grid(row=row, column=0, columnspan=2, pady=(12, 20))

        def do_save():
            """「保存」ボタン: 入力を検証して保存し、ダイアログを閉じる"""
            if not collect(cfg):
                return
            if is_new:
                servers.append(cfg)
                uid = next_uid(cfg)
                add_row(uid)
                poll_uid(uid)
            else:
                uid = uid_for_cfg(cfg)
                if uid is not None:
                    update_row(uid)
                    poll_uid(uid)
            persist()
            refresh_summary()
            root.title(f"{APP_NAME} - サーバー一覧")
            log(f"保存しました: {cfg.server_name} ({cfg.host})")
            win.destroy()

        def do_test_ssh():
            """「接続テスト」ボタン: 現在の入力内容で接続を試す"""
            import copy as _copy
            tmp = _copy.deepcopy(cfg)
            if collect(tmp):
                log("SSH接続テスト中…", tmp)
                def run_ssh_test_async():
                    try:
                        out = ssh_test(tmp, log=lambda m: log(m, tmp))
                        log(f"SSHテスト成功:\n{out}", tmp)
                        post_to_ui(lambda result=out: (
                            messagebox.showinfo(
                                "SSHテスト", f"接続できました\n\n{result}", parent=win)
                            if win.winfo_exists() else None))
                    except Exception as exc:
                        error = str(exc)
                        log(f"SSHテスト失敗: {error}", tmp)
                        post_to_ui(lambda detail=error: (
                            messagebox.showerror("SSHテスト", detail, parent=win)
                            if win.winfo_exists() else None))
                threading.Thread(target=run_ssh_test_async, daemon=True).start()

        wol_test_active = {"value": False}

        def finish_wol_test(error: str | None):
            if not win.winfo_exists():
                return
            wol_test_active["value"] = False
            wol_test_button.configure(state="normal")
            if error:
                messagebox.showerror("WoLテスト", error, parent=win)

        def do_test_wol():
            """「WoL送信テスト」ボタン: 現在の入力内容でマジックパケットを送る"""
            if wol_test_active["value"]:
                return
            import copy as _copy
            tmp = _copy.deepcopy(cfg)
            if collect(tmp):
                wol_test_active["value"] = True
                wol_test_button.configure(state="disabled")
                log("WoLテスト送信中…", tmp)

                def send_wol_async():
                    error = None
                    try:
                        send_wol(tmp, log=lambda m: log(m, tmp))
                        log("WoLテストパケットを送信しました", tmp)
                    except Exception as exc:
                        error = str(exc)
                        log(f"WoLテスト失敗: {error}", tmp)
                    post_to_ui(lambda detail=error: finish_wol_test(detail))

                threading.Thread(target=send_wol_async, daemon=True).start()

        def do_install_key():
            """「公開鍵を登録」ボタン: 鍵認証を使えるようにする"""
            import copy as _copy
            tmp = _copy.deepcopy(cfg)
            if not collect(tmp):
                return
            if (tmp.is_windows and tmp.windows_method == "rpc") or tmp.is_monitor_only():
                messagebox.showinfo("公開鍵登録", "この設定ではSSHを使わないため不要です。",
                                    parent=win)
                return
            log("公開鍵を登録しています… (パスワード認証で接続します)", tmp)

            def run_key_install_async():
                try:
                    priv_path, created = install_public_key(
                        tmp, log=lambda m: log(m, tmp))

                    def on_key_install_done():
                        if not win.winfo_exists():
                            return
                        entries["ssh_key_file"].delete(0, "end")
                        entries["ssh_key_file"].insert(0, priv_path)
                        messagebox.showinfo(
                            "公開鍵登録",
                            ("公開鍵を登録しました。\n" if created
                             else "公開鍵は既に登録済みでした。\n")
                            + f"秘密鍵: {priv_path}\n\n"
                            "「保存」を押すと鍵認証が有効になり、ターミナルが"
                            "パスワード入力なしで開くようになります。", parent=win)
                    post_to_ui(on_key_install_done)
                except Exception as exc:
                    error = str(exc)
                    log(f"公開鍵登録に失敗: {error}", tmp)
                    post_to_ui(lambda detail=error: (
                        messagebox.showerror("公開鍵登録", detail, parent=win)
                        if win.winfo_exists() else None))
            threading.Thread(target=run_key_install_async, daemon=True).start()

        tk.Button(btns, text="保存", font=("Yu Gothic UI", 11, "bold"),
                  width=10, command=do_save).pack(side="left", padx=4)
        tk.Button(btns, text="接続テスト", width=14,
                  command=do_test_ssh).pack(side="left", padx=4)
        wol_test_button = tk.Button(btns, text="WoL送信テスト", width=14,
                                    command=do_test_wol)
        wol_test_button.pack(side="left", padx=4)
        tk.Button(btns, text="キャンセル", width=10,
                  command=win.destroy).pack(side="left", padx=4)
        btns2 = tk.Frame(win)
        btns2.grid(row=row + 1, column=0, columnspan=2, pady=(0, 10))
        tk.Button(btns2, text="🔑 公開鍵を登録 (ターミナルをパスワードなしに)",
                  command=do_install_key).pack(side="left", padx=4)

    log(f"{APP_NAME} v{APP_VERSION} 起動 ({len(servers)}台を管理, 設定: {cfg_path})")
    if not has_paramiko:
        log("paramiko が見つかりません。パスワード認証を使うには: pip install paramiko")
    if not servers:
        log("サーバーが未登録です。「サーバー追加」から登録してください")
        # 0台のときに追加ダイアログを自動で開くことはしない (ユーザーの指示による)

    pump_log()
    pump_ui_queue()
    poll_all()
    update_buttons()
    root.mainloop()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """コマンドライン実行の入口。引数に応じて GUI / 電源操作 / 検索に振り分ける"""
    parser = argparse.ArgumentParser(
        description="WakeDeck - Ubuntu Server の電源を WoL / SSH で操作する (複数サーバー対応)")
    parser.add_argument("--config", type=str, default="",
                        help="config.json のパス (省略時: 本体と同じフォルダ)")
    parser.add_argument("--server", type=str, default="",
                        help="対象サーバー (名前の一部 or --list の番号)")
    parser.add_argument("--all", action="store_true",
                        help="全サーバーを対象にする (--on/--off/--reboot/--status と併用)")
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--on", action="store_true", help="電源ON (WoL送信して起動まで待つ)")
    g.add_argument("--off", action="store_true", help="電源OFF (SSH poweroff)")
    g.add_argument("--reboot", action="store_true", help="再起動 (SSH reboot)")
    g.add_argument("--status", action="store_true", help="状態を表示して終了")
    g.add_argument("--terminal", action="store_true",
                   help="対象サーバーへのSSHターミナルを Windows Terminal で開く")
    g.add_argument("--list", action="store_true", help="登録サーバーと状態を一覧表示して終了")
    g.add_argument("--lookup", type=str, default="",
                   help="IP/ホスト名/MAC を渡すと、引ける情報 (IP/ホスト名/MAC) を全部表示して終了")
    g.add_argument("--scan", action="store_true",
                   help="自分のサブネット (/24) をスキャンして機器一覧 (IP/MAC/ホスト名) を表示")
    parser.add_argument("--no-wait", action="store_true",
                        help="操作後の状態遷移を待たない")
    args = parser.parse_args(argv)

    cfg_path = Path(args.config) if args.config else default_config_path()
    servers, interval = load_servers(cfg_path)

    if args.lookup:
        info = lookup_device(args.lookup)
        print(f"入力: {info['query']} ({info['type']})")
        print(f"IPアドレス : {info['ip'] or '(取得できませんでした)'}")
        print(f"ホスト名   : {info['hostname'] or '(取得できませんでした)'}")
        print(f"MACアドレス: {info['mac'] or '(取得できませんでした)'}")
        print("※ MACが引けるのは同一サブネット内だけです。"
              "相手が起動していない/MAC→IPでスキャンしても見つからない場合は取得できません。")
        return 0 if (info["ip"] or info["mac"]) else 1

    if args.scan:
        local = get_local_ip()
        base = subnet_base(local or "") or (subnet_base(servers[0].host) if servers else None)
        if not base:
            print("自分のサブネットを特定できませんでした。", file=sys.stderr)
            return 2
        print(f"この端末のIP: {local} / スキャン範囲: {base}.1〜254")
        for ip, mac, name in scan_subnet_devices(base):
            registered = next((s.server_name for s in servers if s.host == ip), "")
            suffix = f"  [登録済み: {registered}]" if registered else ""
            print(f"{ip:16} {mac:18} {name}{suffix}")
        return 0

    def show_status(cfg: Config, st: str | None = None) -> int:
        """CLI: 登録サーバーと状態を表で表示する"""
        if st is None:
            st = check_status(cfg)
        print(f"{cfg.server_name} ({cfg.host}): "
              f"{STATUS_LABEL.get(st, ('?', ''))[0]} [{st}]")
        return 0 if st == STATUS_ONLINE else 1

    if args.list:
        if not servers:
            print("登録サーバーがありません。GUIで追加してください。")
            return 0
        rc = 0
        statuses = check_statuses(servers)
        for i, (cfg, st) in enumerate(zip(servers, statuses), 1):
            label = STATUS_LABEL.get(st, ("?", ""))[0]
            print(f"{i}. {cfg.server_name}  {cfg.host}  MAC:{cfg.mac_address}  "
                  f"SSH:{cfg.ssh_user}@{cfg.host}:{cfg.ssh_port}  [{label}]")
            if st != STATUS_ONLINE:
                rc = 1
        return rc

    if args.status and not (args.server or args.all):
        # 対象指定なしの --status は全台表示 (v1では1台だった動作の自然な拡張)
        if not servers:
            print("登録サーバーがありません。", file=sys.stderr)
            return 2
        statuses = check_statuses(servers)
        results = [show_status(cfg, st) for cfg, st in zip(servers, statuses)]
        return max(results)

    if args.on or args.off or args.reboot or args.status or args.terminal:
        if args.all:
            targets = servers
        elif args.server:
            found = find_server(servers, args.server)
            if found is None:
                print(f"サーバーが見つかりません: {args.server} (--list で確認してください)",
                      file=sys.stderr)
                return 2
            targets = [found]
        elif len(servers) == 1:
            targets = servers
        elif not servers:
            print(f"未設定です。先にGUIで設定するか {cfg_path} を編集してください。",
                  file=sys.stderr)
            return 2
        else:
            print("複数サーバーが登録されています。--server <名前/番号> か --all を指定してください。",
                  file=sys.stderr)
            for i, c in enumerate(servers, 1):
                print(f"  {i}. {c.server_name} ({c.host})", file=sys.stderr)
            return 2

        if args.status:
            statuses = check_statuses(targets)
            return max(show_status(cfg, st) for cfg, st in zip(targets, statuses))

        if args.terminal:
            try:
                method = launch_terminal(targets)
                print(f"ターミナルを開きました ({method})")
                return 0
            except Exception as e:
                print(f"エラー: {e}", file=sys.stderr)
                return 1

        rc = 0
        for cfg in targets:
            if not cfg.is_configured:
                print(f"[{cfg.server_name}] 未設定のためスキップします", file=sys.stderr)
                rc = 1
                continue
            print(f"[{cfg.server_name}]")
            try:
                if args.on:
                    ok = power_on(cfg, wait=not args.no_wait)
                else:
                    ok = power_off(cfg, reboot=args.reboot, wait=not args.no_wait)
            except Exception as e:
                print(f"エラー: {e}", file=sys.stderr)
                ok = False
            if not ok:
                rc = 1
        return rc

    run_gui(servers, cfg_path, interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
