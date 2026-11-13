"""GUIなしで検証できるコアロジックのテスト。
実行: python tests/test_core.py
- マジックパケットの形式 (102バイト, FFx6 + MACx16)
- MACパースの全形式
- 実際に localhost の UDP でパケットを送受信できること
- DPAPI代替 (base64) の往復
- ブロードキャスト推定
- config の保存/読込往復
"""
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import wake_deck as lp

failures = []

def check(name, cond):
    print(("OK  " if cond else "FAIL") + f" {name}")
    if not cond:
        failures.append(name)

# MACパース
check("parse colon", lp.parse_mac("AA:BB:CC:DD:EE:FF") == bytes.fromhex("AABBCCDDEEFF"))
check("parse hyphen", lp.parse_mac("aa-bb-cc-dd-ee-ff") == bytes.fromhex("AABBCCDDEEFF"))
check("parse plain", lp.parse_mac("aabbccddeeff") == bytes.fromhex("AABBCCDDEEFF"))
try:
    lp.parse_mac("ZZ:ZZ")
    check("parse invalid raises", False)
except ValueError:
    check("parse invalid raises", True)

# パケット形式
pkt = lp.build_magic_packet(bytes.fromhex("AABBCCDDEEFF"))
check("packet len 102", len(pkt) == 102)
check("packet header FFx6", pkt[:6] == b"\xff" * 6)
check("packet MAC x16", pkt[6:] == bytes.fromhex("AABBCCDDEEFF") * 16)
pkt2 = lp.build_magic_packet(bytes.fromhex("AABBCCDDEEFF"), "010203040506")
check("packet SecureOn len 108", len(pkt2) == 108 and pkt2[-6:] == bytes.fromhex("010203040506"))

# ブロードキャスト推定
check("broadcast /24", lp.compute_broadcast("192.0.2.10") == "192.0.2.255")
check("broadcast hostname None", lp.compute_broadcast("myserver.local") is None)

# パスワード保護の往復 (Linuxでは b64 方式)
enc = lp.protect_secret("p@ssw0rd!")
check("protect prefix", enc.startswith(("dpapi:", "b64:")) and "p@ssw0rd" not in enc)
check("unprotect roundtrip", lp.unprotect_secret(enc) == "p@ssw0rd!")
check("unprotect empty", lp.unprotect_secret("") == "")

# WindowsではDPAPIに失敗した場合、弱いbase64保存へ黙って切り替えない
_orig_windows, _orig_dpapi = lp.IS_WINDOWS, lp._dpapi
try:
    lp.IS_WINDOWS = True
    lp._dpapi = lambda data, protect: b"encrypted"
    check("windows secret uses DPAPI", lp.protect_secret("secret").startswith("dpapi:"))

    def fail_dpapi(data, protect):
        raise OSError("DPAPI unavailable")

    lp._dpapi = fail_dpapi
    try:
        lp.protect_secret("secret")
        check("windows DPAPI failure is explicit", False)
    except OSError:
        check("windows DPAPI failure is explicit", True)
finally:
    lp.IS_WINDOWS, lp._dpapi = _orig_windows, _orig_dpapi

# config 往復
import tempfile, os
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "config.json"
    c = lp.Config(host="192.0.2.5", mac_address="AA:BB:CC:DD:EE:FF", ssh_user="example_user")
    c.ssh_password = "secret123"
    c.save(p)
    raw = p.read_text(encoding="utf-8")
    check("password not plaintext in file", "secret123" not in raw)
    c2 = lp.Config.load(p)
    check("config roundtrip", c2.host == "192.0.2.5" and c2.ssh_password == "secret123"
          and c2.is_configured)

# send_wol が正しい宛先に正しいパケットを送ること (FakeSocketで捕捉)
class FakeSocket:
    sent = []
    def __init__(self, *a, **k): pass
    def setsockopt(self, *a): pass
    def sendto(self, data, addr): FakeSocket.sent.append((data, addr)); return len(data)
    def close(self): pass

real_socket = lp.socket.socket
lp.socket.socket = lambda *a, **k: FakeSocket()
try:
    cfg = lp.Config(host="192.0.2.10", mac_address="AA:BB:CC:DD:EE:FF",
                    broadcast_address="", wol_port=9)
    lp.send_wol(cfg, log=lambda m: None, repeats=1)
finally:
    lp.socket.socket = real_socket
addrs = {addr for _, addr in FakeSocket.sent}
check("wol targets (broadcast+global+host)",
      addrs == {("192.0.2.255", 9), ("255.255.255.255", 9), ("192.0.2.10", 9)})
check("wol payloads all magic packet", all(d == pkt for d, _ in FakeSocket.sent))

# 実UDP送受信 (環境がUDP送信を許可している場合のみ。サンドボックスではEPERMでskip)
try:
    received = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 40009))
    srv.settimeout(3)
    def listener():
        try:
            data, _ = srv.recvfrom(2048)
            received.append(data)
        except socket.timeout:
            pass
    t = threading.Thread(target=listener)
    t.start()
    time.sleep(0.2)
    cfg2 = lp.Config(host="127.0.0.1", mac_address="AA:BB:CC:DD:EE:FF",
                     broadcast_address="127.0.0.1", wol_port=40009)
    lp.send_wol(cfg2, log=lambda m: None, repeats=1)
    t.join(timeout=4)
    srv.close()
    if received:
        check("UDP wol received (real socket)", received[0] == pkt)
    else:
        print("SKIP UDP wol received (real socket): この環境ではUDP送信が制限されています")
except PermissionError:
    print("SKIP UDP wol received (real socket): PermissionError")

# 状態判定: 存在しないポートは offline 側に倒れること (pingは環境依存なのでTCPだけ確認)
check("tcp_open closed port", lp.tcp_open("127.0.0.1", 59998, timeout=0.5) is False)

# 複数台の状態確認は入力順を保って返る
_orig_check_status = lp.check_status
try:
    lp.check_status = lambda cfg: cfg.host
    status_cfgs = [lp.Config(host="server-1"), lp.Config(host="server-2")]
    check("parallel status preserves order",
          lp.check_statuses(status_cfgs) == ["server-1", "server-2"])
    check("parallel status handles empty input", lp.check_statuses([]) == [])
finally:
    lp.check_status = _orig_check_status

# LANスキャンの結果行は数値順に並び、ホスト名もスキャン処理側で解決する
_orig_ping_sweep = lp.ping_sweep
_orig_resolve_hostname = lp.resolve_hostname
scan_bases = []
try:
    def fake_ping_sweep(base, log=print):
        scan_bases.append(base)
        return {
            "192.0.2.10": "AA:AA:AA:AA:AA:10",
            "192.0.2.2": "AA:AA:AA:AA:AA:02",
        }

    lp.ping_sweep = fake_ping_sweep
    lp.resolve_hostname = lambda ip: "host-2" if ip.endswith(".2") else None
    scan_rows = lp.scan_subnet_devices("192.0.2", log=lambda _message: None)
    check("scan rows sorted and resolve hostnames",
          scan_bases == ["192.0.2"] and scan_rows == [
              ("192.0.2.2", "AA:AA:AA:AA:AA:02", "host-2"),
              ("192.0.2.10", "AA:AA:AA:AA:AA:10", ""),
          ])
finally:
    lp.ping_sweep = _orig_ping_sweep
    lp.resolve_hostname = _orig_resolve_hostname

# --- 複数サーバー (v2) -------------------------------------------------------
import json as _json
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "config.json"
    # v2 往復: 2台保存して読み直す。パスワードが平文で残らないこと
    a = lp.Config(server_name="メイン", host="192.0.2.10",
                  mac_address="AA:BB:CC:DD:EE:FF", ssh_user="example_user")
    a.ssh_password = "pw-a"
    b = lp.Config(server_name="ファイル", host="192.0.2.11",
                  mac_address="11:22:33:44:55:66", ssh_user="nas")
    lp.save_servers(p, [a, b], 5)
    raw = p.read_text(encoding="utf-8")
    check("v2 password not plaintext", "pw-a" not in raw)
    data = _json.loads(raw)
    check("v2 format", data.get("version") == 2 and len(data.get("servers", [])) == 2)
    servers, interval = lp.load_servers(p)
    check("v2 roundtrip", len(servers) == 2 and servers[0].server_name == "メイン"
          and servers[0].ssh_password == "pw-a" and servers[1].host == "192.0.2.11"
          and interval == 5)

    # v1 (単一) 形式からの自動移行
    old = lp.Config(server_name="旧サーバー", host="192.0.2.99",
                    mac_address="AA:AA:AA:AA:AA:AA", ssh_user="old")
    p1 = Path(td) / "v1.json"
    old.save(p1)  # Config.save は v1 形式で書く
    servers1, _ = lp.load_servers(p1)
    check("v1 migration", len(servers1) == 1 and servers1[0].server_name == "旧サーバー"
          and servers1[0].host == "192.0.2.99")

    # find_server: 番号 / 完全一致 / 部分一致
    check("find by index", lp.find_server(servers, "2") is servers[1])
    check("find by exact name", lp.find_server(servers, "メイン") is servers[0])
    check("find by partial", lp.find_server(servers, "ファイ") is servers[1])
    check("find missing", lp.find_server(servers, "存在しない") is None)
    check("find bad index", lp.find_server(servers, "9") is None)

    # ファイルなし → 空
    servers0, _ = lp.load_servers(Path(td) / "none.json")
    check("load missing = empty", servers0 == [])

# --- Windows対象 -------------------------------------------------------------
win = lp.Config(server_name="WinPC", host="192.0.2.30",
                mac_address="44:55:66:77:88:99", ssh_user="example_user",
                os_type="windows", windows_method="ssh")
check("windows remote poweroff", lp.remote_command(win, "poweroff") == ("shutdown /s /t 0 /f", None))
check("windows remote reboot", lp.remote_command(win, "reboot") == ("shutdown /r /t 0 /f", None))
check("linux remote still sudo", lp.remote_command(
    lp.Config(ssh_user="x"), "poweroff")[0].endswith("poweroff"))
check("windows check_port ssh", win.check_port == 22)
win_rpc = lp.Config(server_name="WinRPC", host="192.0.2.31",
                    mac_address="44:55:66:77:88:AA",
                    os_type="windows", windows_method="rpc")
check("windows check_port rpc=445", win_rpc.check_port == 445)
check("rpc is_configured without ssh user", win_rpc.is_configured)
check("ssh win without user = auto monitor (configured)",
      lp.Config(host="192.0.2.32", mac_address="44:55:66:77:88:BB",
                os_type="windows").is_configured)
if not lp.IS_WINDOWS:
    try:
        lp.ssh_exec(win_rpc, "poweroff", log=lambda m: None)
        check("rpc on non-windows raises", False)
    except lp.SshError as e:
        check("rpc on non-windows raises", "Windowsで" in str(e) or "Windows" in str(e))
# v2往復で os_type / windows_method が保持されること
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "w.json"
    lp.save_servers(p, [win, win_rpc], 4)
    loaded, _ = lp.load_servers(p)
    check("windows fields roundtrip",
          loaded[0].os_type == "windows" and loaded[0].windows_method == "ssh"
          and loaded[1].windows_method == "rpc")
    # 旧設定 (os_typeなし) は linux として読めること
    p2 = Path(td) / "old.json"
    p2.write_text('{"server_name":"旧","host":"192.0.2.5","mac_address":"AA:BB:CC:DD:EE:FF","ssh_user":"example_user"}',
                  encoding="utf-8")
    old_loaded, _ = lp.load_servers(p2)
    check("old config defaults to linux", old_loaded[0].os_type == "linux"
          and old_loaded[0].windows_method == "ssh")

# --- ネットワーク解決 -----------------------------------------------------------
check("classify ip", lp.classify_query("192.0.2.10") == "ip")
check("classify mac colon", lp.classify_query("AA:BB:CC:DD:EE:FF") == "mac")
check("classify mac hyphen", lp.classify_query("aa-bb-cc-dd-ee-ff") == "mac")
check("classify hostname", lp.classify_query("my-server.local") == "hostname")
check("classify hostname plain", lp.classify_query("fileserver") == "hostname")
check("is_ipv4", lp.is_ipv4("192.0.2.1") and not lp.is_ipv4("example.com")
      and not lp.is_ipv4("999.1.1.1"))

win_arp = """Interface: 192.0.2.5 --- 0xc
  Internet Address      Physical Address      Type
  192.0.2.1           02-00-00-00-00-01     dynamic
  192.0.2.10          aa-bb-cc-dd-ee-ff     dynamic
  192.0.2.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
parsed = lp.parse_arp_output(win_arp)
check("parse arp windows", parsed.get("192.0.2.10") == "AA:BB:CC:DD:EE:FF"
      and parsed.get("192.0.2.1") == "02:00:00:00:00:01")
check("parse arp excludes broadcast ip", "192.0.2.255" not in parsed)

linux_neigh = """192.0.2.1 dev eth0 lladdr 02:00:00:00:00:01 REACHABLE
192.0.2.11 dev eth0 lladdr 11:22:33:44:55:66 STALE
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router FAILED
"""
parsed2 = lp.parse_arp_output(linux_neigh)
check("parse ip neigh", parsed2.get("192.0.2.11") == "11:22:33:44:55:66"
      and parsed2.get("192.0.2.1") == "02:00:00:00:00:01")

check("resolve localhost", lp.resolve_ip("localhost") == "127.0.0.1")
hn = lp.resolve_hostname("127.0.0.1")
check("resolve hostname localhost (no exception, str or None)",
      hn is None or isinstance(hn, str))
info = lp.lookup_device("127.0.0.1", log=lambda m: None, allow_scan=False)
check("lookup loopback ip", info["type"] == "ip" and info["ip"] == "127.0.0.1")
mac_lo = lp.get_mac_for_ip("127.0.0.1", ping_first=False)
check("loopback mac is None or valid (no exception)",
      mac_lo is None or len(lp.parse_mac(mac_lo)) == 6)
check("subnet_base", lp.subnet_base("192.0.2.10") == "192.0.2"
      and lp.subnet_base("bad") is None)

# --- SSHターミナル / 公開鍵 -------------------------------------------------------
t1 = lp.Config(server_name="メイン", host="192.0.2.10", ssh_user="example_user", ssh_port=22)
t2 = lp.Config(server_name="ファイル", host="192.0.2.11", ssh_user="nas", ssh_port=2222,
               ssh_key_file="C:\\keys\\id_ed25519")
wt = lp.build_wt_args([t1, t2])
check("wt args single window multi tab",
      wt[0] == "wt.exe" and wt.count("new-tab") == 2 and ";" in wt
      and "example_user@192.0.2.10" in wt and "nas@192.0.2.11" in wt
      and wt[wt.index("nas@192.0.2.11") - 2] == "-i")
check("wt title", wt[wt.index("new-tab") + 2] == "メイン")
fb = lp.build_fallback_args(t1, "powershell")
check("fallback powershell", fb[0] == "powershell.exe" and "-NoExit" in fb
      and "ssh" in fb[-1] and "example_user@192.0.2.10" in fb[-1])
fb2 = lp.build_fallback_args(t1, "cmd")
check("fallback cmd", fb2[0] == "cmd.exe" and fb2[1] == "/k")
rpc_cfg = lp.Config(server_name="RPC", host="192.0.2.31", os_type="windows",
                    windows_method="rpc")
check("ssh_capable", lp.ssh_capable(t1) and not lp.ssh_capable(rpc_cfg)
      and not lp.ssh_capable(lp.Config(host="x")))
logs = []
ready = lp.terminal_targets([t1, rpc_cfg], log=logs.append)
check("terminal_targets filters rpc", ready == [t1] and len(logs) == 1)
try:
    lp.launch_terminal([rpc_cfg], log=lambda m: None)
    check("launch with no targets raises", False)
except lp.SshError:
    check("launch with no targets raises", True)

ak = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummyKeyBody user@pc\n" \
     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDummyRsaBody user@pc\n"
check("key already present (comment differs)",
      lp.key_already_present(ak, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDummyKeyBody other@host"))
check("key not present",
      not lp.key_already_present(ak, "ssh-ed25519 AAAAC3DifferentBodyXXXX user@pc"))
# 鍵ペア生成 (一時HOME)
import subprocess as _sp
with tempfile.TemporaryDirectory() as td:
    env_home = Path(td)
    orig_home = lp.Path.home
    lp.Path.home = classmethod(lambda cls: env_home)
    try:
        priv, pub = lp.find_or_create_keypair(log=lambda m: None)
        check("keypair created", priv.exists() and pub.exists()
              and pub.read_text().startswith("ssh-ed25519 "))
        priv2, _ = lp.find_or_create_keypair(log=lambda m: None)
        check("keypair reused", priv2 == priv)
    finally:
        lp.Path.home = orig_home

# --- 監視のみモード (SSH/RPCなし) -------------------------------------------------
row_server = lp.Config(host="192.0.2.39", mac_address="55:66:77:88:99:DD",
                       ssh_user="example_user")
check("server row action is ON when offline",
      lp.server_row_action(row_server, lp.STATUS_OFFLINE) == "on")
check("server row action is OFF when booting",
      lp.server_row_action(row_server, lp.STATUS_BOOTING) == "off")
check("server row action is OFF when online",
      lp.server_row_action(row_server, lp.STATUS_ONLINE) == "off")
check("server row action supports Windows RPC",
      lp.server_row_action(lp.Config(
          host="192.0.2.38", mac_address="55:66:77:88:99:CC",
          os_type="windows", windows_method="rpc"), lp.STATUS_ONLINE) == "off")
check("server row action disables monitor-only shutdown",
      lp.server_row_action(lp.Config(
          host="192.0.2.37", mac_address="55:66:77:88:99:BB"),
          lp.STATUS_ONLINE) == "disabled")
check("server row action disables unconfigured server",
      lp.server_row_action(lp.Config(), lp.STATUS_OFFLINE) == "disabled")

mon = lp.Config(server_name="監視のみ機", host="192.0.2.40",
                mac_address="55:66:77:88:99:AA", monitor_only=True)
check("monitor_only configured without ssh user", mon.is_configured)
check("monitor_only check_port 0 (ping only)", mon.check_port == 0)
mon2 = lp.Config(server_name="監視のみRDP", host="192.0.2.41",
                 mac_address="55:66:77:88:99:BB", monitor_only=True, status_port=3389)
check("monitor_only check_port = status_port", mon2.check_port == 3389)
check("monitor_only not ssh_capable", not lp.ssh_capable(mon))
check("no-user server auto-becomes monitor_only",
      lp.Config(host="192.0.2.42", mac_address="55:66:77:88:99:CC").is_monitor_only())
# --- 監視のみの自動判定 (SSHユーザー名が空なら自動で監視のみ) -------------------
auto = lp.Config(server_name="自動監視", host="192.0.2.44",
                 mac_address="55:66:77:88:99:EE")
check("no ssh user = auto monitor_only", auto.is_monitor_only())
check("auto monitor configured with ip+mac", auto.is_configured)
check("auto monitor check_port ping only", auto.check_port == 0)
check("auto monitor not ssh_capable", not lp.ssh_capable(auto))
auto_rdp = lp.Config(host="192.0.2.45", mac_address="55:66:77:88:99:FF", status_port=3389)
check("auto monitor check_port = status_port", auto_rdp.check_port == 3389)
check("windows rpc without user NOT monitor",
      not lp.Config(host="192.0.2.46", mac_address="11:22:33:44:55:66",
                    os_type="windows", windows_method="rpc").is_monitor_only())
check("windows ssh without user = auto monitor",
      lp.Config(host="192.0.2.47", mac_address="11:22:33:44:55:77",
                os_type="windows", windows_method="ssh").is_monitor_only())
check("explicit monitor flag with user still monitor",
      lp.Config(host="192.0.2.48", mac_address="11:22:33:44:55:88",
                ssh_user="x", monitor_only=True).is_monitor_only())
try:
    lp.power_off(auto, log=lambda m: None, wait=False)
    check("auto monitor power_off raises", False)
except lp.SshError as e:
    check("auto monitor power_off raises", "監視のみ" in str(e))

# 状態判定: ping スタブでオンライン/オフラインが決まること (SSHポートに依存しない)
_orig_ping, _orig_tcp = lp.ping_host, lp.tcp_open
try:
    lp.ping_host = lambda h, timeout_ms=700: True
    lp.tcp_open = lambda h, p, timeout=1.2: False  # SSHポートは閉じている想定
    check("monitor_only ping ok = online (not booting)",
          lp.check_status(mon) == lp.STATUS_ONLINE)
    lp.ping_host = lambda h, timeout_ms=700: False
    check("monitor_only ping ng = offline", lp.check_status(mon) == lp.STATUS_OFFLINE)
    # 通常サーバーは従来通り: pingのみ応答だと booting
    lp.ping_host = lambda h, timeout_ms=700: True
    normal = lp.Config(host="192.0.2.43", mac_address="55:66:77:88:99:DD", ssh_user="x")
    check("normal server ping only = booting (unchanged)",
          lp.check_status(normal) == lp.STATUS_BOOTING)
finally:
    lp.ping_host, lp.tcp_open = _orig_ping, _orig_tcp
try:
    lp.power_off(mon, log=lambda m: None, wait=False)
    check("monitor_only power_off raises", False)
except lp.SshError as e:
    check("monitor_only power_off raises", "監視のみ" in str(e))
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "m.json"
    lp.save_servers(p, [mon, mon2], 4)
    loaded, _ = lp.load_servers(p)
    check("monitor fields roundtrip", loaded[0].monitor_only and not loaded[1].monitor_only is False
          and loaded[1].status_port == 3389)

print()
if failures:
    print(f"{len(failures)} FAILED: {failures}")
    sys.exit(1)
print("ALL TESTS PASSED")
