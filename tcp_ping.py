import socket
import time
import sys

def tcp_ping(host, port, timeout=2, count=4, ip_version=4):
    """
    支持IPv6的TCP Ping实现
    
    参数:
        host: 目标主机（域名或IP地址）
        port: 目标端口
        timeout: 超时时间（秒）
        count: 尝试次数
        ip_version: IP版本（4=IPv4, 6=IPv6）
    """
    print(f"正在 TCP Ping {host}:{port} (IPv{ip_version})，共 {count} 次尝试...\n")
    
    # 设置地址族
    if ip_version == 6:
        family = socket.AF_INET6
        ip_type = "IPv6"
    else:
        family = socket.AF_INET
        ip_type = "IPv4"
    
    success = 0
    failed = 0
    times = []
    
    for i in range(count):
        start_time = time.time()
        try:
            # 创建对应IP版本的TCP套接字
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                # 设置超时
                sock.settimeout(timeout)
                
                # 尝试连接
                result = sock.connect_ex((host, port))
                
                if result == 0:
                    # 连接成功，获取本地和远程地址信息
                    local_addr, remote_addr = sock.getsockname(), sock.getpeername()
                    end_time = time.time()
                    delay = (end_time - start_time) * 1000  # 转换为毫秒
                    times.append(delay)
                    success += 1
                    print(f"来自 {remote_addr[0]} 的回复: 时间 = {delay:.2f} ms")
                else:
                    # 连接失败（端口关闭）
                    failed += 1
                    print(f"无法连接到 {host}:{port} (端口关闭)")
                    
        except socket.timeout:
            # 超时
            failed += 1
            print(f"连接 {host}:{port} 超时 (> {timeout*1000} ms)")
        except socket.gaierror as e:
            # 域名解析失败（可能不支持IPv6）
            failed += 1
            print(f"域名解析失败: {str(e)} (可能不支持{ip_type})")
        except OSError as e:
            # 地址相关错误（如IPv6未启用）
            failed += 1
            print(f"网络错误: {str(e)}")
        except Exception as e:
            # 其他错误
            failed += 1
            print(f"错误: {str(e)}")
        
        # 两次尝试之间间隔1秒
        if i < count - 1:
            time.sleep(1)
    
    # 输出统计信息
    print(f"\n--- {host}:{port} {ip_type} TCP Ping 统计信息 ---")
    print(f"    数据包: 已发送 = {count}, 已接收 = {success}, 丢失 = {failed} ({failed/count*100:.0f}% 丢失)")
    
    if success > 0:
        print(f"往返行程的估计时间（毫秒）:")
        print(f"    最小值 = {min(times):.2f}ms, 最大值 = {max(times):.2f}ms, 平均值 = {sum(times)/success:.2f}ms")

# 示例使用
if __name__ == "__main__":
    # 测试IPv4（百度）
    #tcp_ping("www.baidu.com", 80, count=3, ip_version=4)
    #print("\n" + "-"*60 + "\n")
    
    # 测试IPv6（百度IPv6地址，需网络支持）
    # 注意：需网络环境支持IPv6才能成功
    #tcp_ping("www.baidu.com", 80, count=3, ip_version=6)
    #print("\n" + "-"*60 + "\n")
    
    # 测试纯IPv6域名（如IPv6测试站点）
    try:
        tcp_ping("ipv6.test-ipv6.com", 80, count=3, ip_version=6)
         # tcp_ping("localhost", 3306)
        tcp_ping("0mhkiml6.fn.bytedance.net", 443)
        tcp_ping("10.8.7.220", 443)
        tcp_ping("fdbd:dc01:00fe:1009:0000:0000:0000:0001", 443,count=3, ip_version=6)
    except Exception as e:
        print(f"IPv6测试失败: {e}")


   
