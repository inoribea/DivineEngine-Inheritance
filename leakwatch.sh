#!/bin/sh
usage() { cat <<U
用法: sh $0 [-i 网卡] [-4] [-t 目标IPv4] [-s 设备IPv4] [-x "排除IP ..."] [-k secret] [-p API端口]
  -i  WAN 网卡（默认自动识别）
  -4  只抓 IPv4
  -t  只看与这个外部 IPv4 之间的流量
  -s  设备模式：从 mihomo 连接表列出这台设备走 DIRECT 的连接（需要 curl 和 jq）
  -x  排除的 IP，比如节点 IP，用空格分隔
  -k  mihomo 的 secret；-p  API 端口，默认 9090
U
exit 1; }

is_ipv4() { echo "$1" | awk -F. 'NF!=4{exit 1} {for(i=1;i<=4;i++) if($i!~/^[0-9]+$/ || $i>255) exit 1}'; }

WAN=""; V4=""; TGT=""; SRC=""; XL=""; KEY=""; PORT=9090
while getopts "i:4t:s:x:k:p:h" o; do
  case "$o" in
    i) WAN="$OPTARG" ;;  4) V4=1 ;;  t) TGT="$OPTARG" ;;  s) SRC="$OPTARG" ;;
    x) XL="$OPTARG" ;;   k) KEY="$OPTARG" ;;  p) PORT="$OPTARG" ;;  *) usage ;;
  esac
done

[ -n "$WAN" ] || WAN="$(ip route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
[ -n "$WAN" ] || { echo "!!! 找不到 WAN 网卡，请用 -i 指定"; exit 1; }
command -v tcpdump >/dev/null 2>&1 || { echo "!!! 没装 tcpdump"; exit 1; }
for ip in $TGT $SRC $XL; do is_ipv4 "$ip" || { echo "!!! 不是合法的 IPv4: $ip"; exit 1; }; done

# 公共过滤条件：IPv4 限定、目标 IP、排除列表
FIX=""
[ -n "$V4" ]  && FIX="ip"
[ -n "$TGT" ] && FIX="${FIX:+$FIX and }host $TGT"
for ip in $XL; do FIX="${FIX:+$FIX and }not host $ip"; done
mk() { echo "($1)${FIX:+ and $FIX}"; }

F_HTTP="$(mk 'tcp dst port 80 or tcp dst port 8080')"
F_DNS="$(mk 'port 53')"
F_TLS="$(mk 'tcp dst port 443 and (tcp[((tcp[12]&0xf0)>>2)]=0x16)')"
for f in "$F_HTTP" "$F_DNS" "$F_TLS"; do
  tcpdump -i "$WAN" -d "$f" >/dev/null || { echo "!!! 过滤器编译失败: $f"; exit 1; }
done

# 设备模式要先确认 API 能访问
if [ -n "$SRC" ]; then
  command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 || { echo "!!! -s 需要: opkg install curl jq"; exit 1; }
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $KEY" "http://127.0.0.1:$PORT/connections")"
  [ "$code" = "200" ] || { echo "!!! mihomo API 返回 $code（401 表示 -k 的 secret 不对；000 表示 -p 端口不对）"; exit 1; }
fi

echo ">>> WAN=$WAN ${V4:+[仅IPv4] }${TGT:+[目标 $TGT] }${SRC:+[设备 $SRC] }（Ctrl+C 结束）"
echo ">>> 下面应出现 3 行 listening on $WAN"
trap 'kill 0 2>/dev/null; exit 0' INT TERM

tcpdump -i "$WAN" -nn -l -A -s0 "$F_HTTP" |
awk '/(GET|POST|HEAD|PUT) \/|Host:|imei=|phone=|imsi=|oaid=|idfa=/ {print "[HTTP明文] " $0; fflush()}' &

tcpdump -i "$WAN" -nn -l "$F_DNS" |
awk '{print "[明文DNS] " $0; fflush()}' &

tcpdump -i "$WAN" -nn -l -A -s0 "$F_TLS" |
awk '{ s=$0; while (match(s, /[a-z0-9-]+(\.[a-z0-9-]+)+\.(com|cn|net|org|io|top|me|tv|ing)/)) {
        print "[TLS-SNI] " substr(s, RSTART, RLENGTH); fflush(); s=substr(s, RSTART+RLENGTH) } }' &

if [ -n "$SRC" ]; then
  ( while :; do
      curl -s -H "Authorization: Bearer $KEY" "http://127.0.0.1:$PORT/connections" |
      jq -r --arg s "$SRC" '.connections[]?
        | select(.metadata.sourceIP == $s and .chains[0] == "DIRECT")
        | "\(.metadata.destinationPort)\t\(.metadata.host // "-")\t\(.metadata.destinationIP)\t\(.rule) \(.rulePayload)"'
      sleep 2
    done ) |
  awk -F'\t' '!seen[$1 FS $2 FS $3]++ {
      t = ($1==80 || $1==8080) ? "[设备HTTP明文]" : ($1==53 ? "[设备明文DNS]" : (($1==443 || $1==8443) ? "[设备直连SNI]" : "[设备直连]"))
      print t " " $2 " (" $3 ":" $1 ") <- " $4; fflush() }' &
fi

wait
echo "!!! 所有监听进程都已退出，请检查上面的报错"
