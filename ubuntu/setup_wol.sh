#!/bin/bash
# Ubuntu Server 側の事前設定スクリプト
# 使い方: sudo bash setup_wol.sh
# やること:
#   1. Wake on LAN を有効化し、再起動後も維持される systemd サービスを登録
#   2. openssh-server が無ければ導入案内を表示
#   3. MACアドレスとIPを表示 (Windows側の設定に入力する値)
set -e
if [ "$(id -u)" -ne 0 ]; then echo "sudo で実行してください: sudo bash setup_wol.sh"; exit 1; fi

IFACE=$(ip -o route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' || true)
if [ -z "$IFACE" ]; then IFACE=$(ls /sys/class/net | grep -v lo | head -1); fi
echo "対象インターフェース: $IFACE"

if ! command -v ethtool >/dev/null; then
  echo "ethtool をインストールします..."
  apt-get update -qq && apt-get install -y -qq ethtool
fi

ethtool -s "$IFACE" wol g || true
echo "現在のWoL状態:"
ethtool "$IFACE" | grep -i wake || true

cat > /etc/systemd/system/wol.service <<EOF
[Unit]
Description=Enable Wake on LAN ($IFACE)
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ethtool -s $IFACE wol g
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable wol.service
echo "wol.service を有効化しました (再起動後も WoL 有効を維持)"

if ! systemctl is-active --quiet ssh && ! systemctl is-active --quiet sshd; then
  echo ""
  echo "[注意] SSHサーバーが動いていません。以下を実行してください:"
  echo "  sudo apt install -y openssh-server && sudo systemctl enable --now ssh"
fi

echo ""
echo "==== Windows側 WakeDeck の設定に入れる値 ===="
echo "IPアドレス : $(hostname -I | awk '{print $1}')"
echo "MACアドレス: $(cat /sys/class/net/$IFACE/address | tr 'a-f' 'A-F')"
echo "SSHユーザー: $(logname 2>/dev/null || echo '(あなたのユーザー名)')"
echo ""
echo "推奨: ルーターのDHCP固定割当でこのIPを固定してください。"
echo "任意: パスワードなしで電源OFFしたい場合は次を visudo に追加:"
echo "  $(logname 2>/dev/null || echo USER) ALL=(ALL) NOPASSWD: /usr/sbin/poweroff, /usr/sbin/reboot"
echo "  ※ アプリは sudo -S でパスワードを渡す方式がデフォルトなので、これは任意です"
