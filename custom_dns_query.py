import socket
import struct
import random

def query_dns(domain, dns_server, qtype=1):
    """
    向指定DNS服务器查询域名的IP地址
    
    参数:
        domain: 待查询的域名（如 'www.baidu.com'）
        dns_server: DNS服务器地址（如 '8.8.8.8' 或 '114.114.114.114'）
        qtype: 查询类型（1=A记录IPv4, 28=AAAA记录IPv6）
    
    返回:
        解析到的IP地址列表（IPv4字符串或IPv6字符串）
    """
    # 1. 构建DNS请求包
    # 事务ID（随机16位）
    transaction_id = random.randint(0, 0xFFFF)
    # 标志位：标准查询（0x0100）
    flags = 0x0100
    # 问题数：1
    qdcount = 1
    # 资源记录数：0（请求不需要）
    ancount = 0
    nscount = 0
    arcount = 0
    
    # 打包DNS头部（12字节）
    header = struct.pack('!HHHHHH', transaction_id, flags, qdcount, ancount, nscount, arcount)
    
    # 构建问题部分：域名编码（如 www.baidu.com -> 3www5baidu3com0）
    qname = b''
    for part in domain.split('.'):
        qname += struct.pack('B', len(part)) + part.encode('utf-8')
    qname += b'\x00'  # 域名结束标志
    
    # 查询类型（1=A记录）和查询类（1=IN互联网）
    qtype = qtype  # 1=A记录(IPv4), 28=AAAA(IPv6)
    qclass = 1
    question = qname + struct.pack('!HH', qtype, qclass)
    
    # 完整请求数据
    request = header + question
    
    # 2. 发送请求到DNS服务器（UDP端口53）
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)  # 5秒超时
        sock.sendto(request, (dns_server, 53))
        response, _ = sock.recvfrom(1024)  # 接收响应（最大1024字节）
    
    # 3. 解析响应
    # 解析头部
    header = response[:12]
    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', header)
    
    # 检查响应是否匹配请求ID
    if tid != transaction_id:
        raise RuntimeError("DNS响应ID不匹配，可能是过期响应")
    
    # 检查标志位是否为成功响应
    if (flags & 0x8000) == 0:
        raise RuntimeError("未收到DNS服务器响应")
    if (flags & 0x000F) != 0:
        errors = {1: "格式错误", 2: "服务器失败", 3: "域名不存在", 4: "不支持的操作"}
        err = errors.get(flags & 0x000F, f"未知错误 ({flags & 0x000F})")
        raise RuntimeError(f"DNS查询失败: {err}")
    
    # 跳过问题部分（定位到资源记录）
    ptr = 12  # 头部长度12字节
    # 跳过域名（处理压缩格式）
    while True:
        byte = response[ptr]
        if byte == 0:
            ptr += 1
            break
        # 处理压缩（最高两位为1表示指针）
        if (byte & 0xC0) == 0xC0:
            ptr += 2
            break
        ptr += 1 + byte  # 跳过标签长度和内容
    ptr += 4  # 跳过qtype和qclass（各2字节）
    
    # 解析资源记录（回答部分）
    ips = []
    for _ in range(ancount):
        # 跳过域名（可能是压缩格式）
        while True:
            byte = response[ptr]
            if byte == 0:
                ptr += 1
                break
            if (byte & 0xC0) == 0xC0:
                ptr += 2
                break
            ptr += 1 + byte
        
        # 解析资源记录头部
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', response[ptr:ptr+10])
        ptr += 10
        
        # 提取IP地址
        rdata = response[ptr:ptr+rdlength]
        ptr += rdlength
        
        # 处理A记录（IPv4）
        if rtype == 1 and rclass == 1:
            if rdlength == 4:
                ip = '.'.join(map(str, rdata))
                ips.append(ip)
        # 处理AAAA记录（IPv6）
        elif rtype == 28 and rclass == 1:
            if rdlength == 16:
                ip_parts = struct.unpack('!HHHHHHHH', rdata)
                ip = ':'.join(f'{p:04x}' for p in ip_parts)
                ips.append(ip)
    
    return ips


# 示例使用
if __name__ == "__main__":
    # 测试配置
    test_domains = [
        "www.baidu.com",
        "www.github.com",
        "www.google.com",
        "0mhkiml6.fn.bytedance.net"
    ]
    dns_servers = [
        #"114.114.114.114",  # 114DNS
        "8.8.8.8",          # Google DNS
        "223.5.5.5"         # 阿里云DNS
    ]
    
    for domain in test_domains:
        print(f"--- 域名: {domain} ---")
        for dns in dns_servers:
            try:
                # 查询IPv4地址（A记录）
                ipv4 = query_dns(domain, dns, qtype=1)
                # 查询IPv6地址（AAAA记录，可选）
                ipv6 = query_dns(domain, dns, qtype=28)
                
                print(f"DNS服务器 {dns}:")
                print(f"  IPv4: {ipv4 if ipv4 else '未找到记录'}")
                print(f"  IPv6: {ipv6 if ipv6 else '未找到记录'}")
            except Exception as e:
                print(f"DNS服务器 {dns} 错误: {str(e)}")
        print()  # 空行分隔
