from scapy.all import get_if_list, sniff
import time

def test_npcap():
    try:
        # 获取可用网络接口列表
        interfaces = get_if_list()
        if not interfaces:
            print("未找到任何网络接口，Npcap可能未安装或未正常工作")
            return False
        
        print("检测到可用网络接口：")
        for i, iface in enumerate(interfaces):
            print(f"  {i+1}. {iface}")
        
        # 尝试捕获1个数据包（10秒超时）
        print("\n尝试捕获1个数据包（10秒内）...")
        # 移除verbose参数以兼容所有Scapy版本
        packet = sniff(count=1, timeout=10)
        
        if packet:
            print("捕获成功！Npcap工作正常")
            return True
        else:
            print("10秒内未捕获到数据包（可能网络无活动，或Npcap安装有问题）")
            # 提供额外的排查建议
            print("\n排查建议：")
            print("1. 确保以管理员身份运行脚本")
            print("2. 检查网络是否有活动（如浏览网页）")
            print("3. 确认Npcap安装时勾选了'WinPcap兼容模式'")
            return False
    
    except Exception as e:
        print(f"捕获失败，错误信息：{str(e)}")
        # 针对常见错误提供解决方案
        if "permission denied" in str(e).lower():
            print("提示：可能缺少管理员权限，请以管理员身份运行")
        elif "no interface found" in str(e).lower():
            print("提示：未找到网络接口，请重新安装Npcap")
        return False

if __name__ == "__main__":
    test_npcap()
