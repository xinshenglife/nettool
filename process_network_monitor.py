import psutil
import socket
import argparse
import sys
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
from scapy.layers.http import HTTPRequest, HTTPResponse
import threading
from contextlib import contextmanager

# 全局状态管理
_monitoring_state = {
    "active": False,
    "connections": set(),
    "lock": threading.Lock(),
    "pid": None,
    "process_info": None
}

def get_process_info(pid=None, process_name=None):
    """获取进程基本信息（支持PID或名称）"""
    if pid:
        try:
            proc = psutil.Process(pid)
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'status': proc.status(),
                'created': datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    if process_name:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if process_name.lower() in proc.info['name'].lower():
                    return get_process_info(pid=proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    return None

def find_process_pid(process_name):
    """通过名称查找进程PID"""
    pids = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if process_name.lower() in proc.info['name'].lower():
                pids.append(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return pids

def update_connections(pid):
    """更新进程的网络连接信息"""
    connections = set()
    for conn in psutil.net_connections(kind='inet'):
        if conn.pid == pid and conn.laddr and conn.raddr:
            proto = 'tcp' if conn.type == socket.SOCK_STREAM else 'udp'
            conn_tuple = (
                conn.laddr.ip, conn.laddr.port,
                conn.raddr.ip, conn.raddr.port,
                proto
            )
            connections.add(conn_tuple)
    return connections

def connection_updater(interval=3):
    """后台更新连接的线程函数"""
    while _monitoring_state["active"]:
        if _monitoring_state["pid"]:
            new_connections = update_connections(_monitoring_state["pid"])
            with _monitoring_state["lock"]:
                _monitoring_state["connections"] = new_connections
        threading.Event().wait(interval)

def is_process_packet(packet):
    """判断数据包是否属于监控进程"""
    if not packet.haslayer(IP):
        return False
    
    ip = packet[IP]
    proto = 'tcp' if packet.haslayer(TCP) else 'udp' if packet.haslayer(UDP) else None
    if not proto:
        return False
    
    src_ip, dst_ip = ip.src, ip.dst
    src_port, dst_port = 0, 0
    
    if proto == 'tcp':
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif proto == 'udp':
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    
    with _monitoring_state["lock"]:
        return (
            (src_ip, src_port, dst_ip, dst_port, proto) in _monitoring_state["connections"] or
            (dst_ip, dst_port, src_ip, src_port, proto) in _monitoring_state["connections"]
        )

def packet_analyzer(packet, detailed=False):
    """解析并显示数据包信息（使用detailed替代verbose避免命名冲突）"""
    if not is_process_packet(packet):
        return None
    
    result = {
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
        "layers": [],
        "summary": []
    }
    
    # 以太网层
    if packet.haslayer(Ether):
        eth = packet[Ether]
        eth_info = f"Ether: {eth.src} -> {eth.dst} (Type: 0x{eth.type:04x})"
        result["summary"].append(eth_info)
        result["layers"].append({"type": "Ethernet", "src": eth.src, "dst": eth.dst, "type": eth.type})
    
    # IP层
    if packet.haslayer(IP):
        ip = packet[IP]
        ip_info = f"IP: {ip.src} -> {ip.dst} (TTL: {ip.ttl}, Proto: {ip.proto})"
        result["summary"].append(ip_info)
        result["layers"].append({"type": "IP", "src": ip.src, "dst": ip.dst, 
                                "ttl": ip.ttl, "protocol": ip.proto})
        
        # TCP层
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = ''.join([f for f, v in tcp.flags.fields.items() if v])
            tcp_info = f"TCP: {tcp.sport} -> {tcp.dport} (Flags: {flags}, Seq: {tcp.seq})"
            result["summary"].append(tcp_info)
            result["layers"].append({"type": "TCP", "src_port": tcp.sport, "dst_port": tcp.dport,
                                    "flags": flags, "seq": tcp.seq})
            
            # HTTP解析
            if packet.haslayer(HTTPRequest):
                req = packet[HTTPRequest]
                http_info = f"HTTP Request: {req.Method.decode()} {req.Path.decode()}"
                result["summary"].append(http_info)
                result["layers"].append({"type": "HTTP Request", 
                                        "method": req.Method.decode(), 
                                        "path": req.Path.decode()})
            elif packet.haslayer(HTTPResponse):
                res = packet[HTTPResponse]
                http_info = f"HTTP Response: {res.Status_Code.decode()} {res.Reason_Phrase.decode()}"
                result["summary"].append(http_info)
                result["layers"].append({"type": "HTTP Response", 
                                        "status": res.Status_Code.decode(), 
                                        "reason": res.Reason_Phrase.decode()})
        
        # UDP层
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            udp_info = f"UDP: {udp.sport} -> {udp.dport} (Len: {udp.len})"
            result["summary"].append(udp_info)
            result["layers"].append({"type": "UDP", "src_port": udp.sport, 
                                    "dst_port": udp.dport, "length": udp.len})
        
        # ICMP层
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            icmp_info = f"ICMP: Type {icmp.type}, Code {icmp.code}"
            result["summary"].append(icmp_info)
            result["layers"].append({"type": "ICMP", "type": icmp.type, "code": icmp.code})
    
    # 负载信息
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            payload_info = f"Payload: {payload[:100]}..." if len(payload) > 100 else f"Payload: {payload}"
            result["summary"].append(payload_info)
        except:
            result["summary"].append("Payload: 二进制数据")
    
    # 打印摘要信息
    print(f"[{result['timestamp']}] | ".join(result["summary"]))
    
    if detailed:
        print("详细信息:", result["layers"], "\n")
    
    return result

@contextmanager
def process_monitor_context(pid):
    """监控上下文管理器，处理线程生命周期"""
    global _monitoring_state
    
    _monitoring_state["active"] = True
    _monitoring_state["pid"] = pid
    _monitoring_state["process_info"] = get_process_info(pid=pid)
    _monitoring_state["connections"] = update_connections(pid)
    
    updater_thread = threading.Thread(target=connection_updater, daemon=True)
    updater_thread.start()
    
    try:
        yield _monitoring_state["process_info"]
    finally:
        _monitoring_state["active"] = False
        updater_thread.join()
        _monitoring_state["pid"] = None
        _monitoring_state["connections"].clear()

def start_process_monitor(pid=None, process_name=None, interface=None, count=0, detailed=False):
    """启动进程网络监控（主函数，使用detailed参数）"""
    if not pid and process_name:
        pids = find_process_pid(process_name)
        if not pids:
            print(f"未找到名称包含 '{process_name}' 的进程")
            return
        if len(pids) > 1:
            print(f"找到多个匹配进程: {pids}")
            pid = int(input("请输入要监控的PID: "))
        else:
            pid = pids[0]
    
    if not pid:
        print("必须指定进程PID或名称")
        return
    
    proc_info = get_process_info(pid=pid)
    if not proc_info:
        print(f"进程不存在或无法访问 (PID: {pid})")
        return
    
    print(f"=== 监控进程: {proc_info['name']} (PID: {pid}) ===")
    print(f"路径: {proc_info['exe']}")
    print(f"状态: {proc_info['status']}")
    print(f"启动时间: {proc_info['created']}\n")
    
    # 完全移除sniff函数中的verbose参数
    with process_monitor_context(pid):
        try:
            sniff(
                iface=interface,
                prn=lambda pkt: packet_analyzer(pkt, detailed),
                count=count,
                store=0  # 仅保留必要参数，移除所有verbose相关
            )
        except KeyboardInterrupt:
            print("\n监控已手动停止")

def main():
    # 权限检查
    if sys.platform.startswith('win32'):
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("警告：请以管理员身份运行以确保正常捕获数据包")
        except:
            pass
    #Wireshark风格的进程网络监控工具
    pid=''#进程PID
    process_name='chrome'#进程名称（模糊匹配）
    interface="WLAN"
    #网络接口  test_npcap.py 得到网络接口列表中找
    count=10 #捕获包数量
    detailed=True
    # 启动监控
    start_process_monitor(
        pid=pid,
        process_name=process_name,
        interface=interface,  
        count=count,
        detailed=detailed
    )

if __name__ == "__main__":
    main()
