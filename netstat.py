import psutil

def get_tcp_connections():
    # 获取所有 TCP 连接
    connections = psutil.net_connections(kind='tcp')
    
    print(f"{'本地地址':<30} {'远程地址':<30} {'状态':<10} {'PID':<6} {'进程名'}")
    print("-" * 90)
    
    for conn in connections:
        # 本地地址和端口
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "0.0.0.0:0"
        # 远程地址和端口
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "0.0.0.0:0"
        # 连接状态
        status = conn.status
        # 进程信息
        pid = conn.pid or "N/A"
        name = ""
        if pid != "N/A":
            try:
                process = psutil.Process(pid)
                name = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "未知"
    
        print(f"{laddr:<30} {raddr:<30} {status:<10} {pid:<6} {name}")

if __name__ == "__main__":
    get_tcp_connections()