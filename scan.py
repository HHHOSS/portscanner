"""
端口扫描器 —— 基于 socket connect_ex 的 TCP 端口扫描脚本。
用法: python3 scan.py <目标IP> <起始端口> <结束端口>
"""

import socket
import sys
import datetime
import json
import os
import threading
import queue

CLOSED_CODES  = {111, 10061}
TIMEOUT_CODES = {110, 10035}


def make_filename(target):
    """
    返回文件名  格式：scan_<ip>_<生成时间>.json
    """
    now = datetime.datetime.now()
    text = now.strftime("%Y%m%d_%H%M%S")
    safe_ip = target.replace(".", "_")   
    return f"scan_{safe_ip}_{text}.json"


def scan_port(target, port):
    """
    扫描单个端口
    返回字典{"port": 端口/int, "status": 状态/str, "code": 错误码/int}
    """

    s = socket.socket()
    s.settimeout(2)
    result = s.connect_ex((target, port))
    s.close()  # 必须关 —— 否则扫大量端口会耗尽资源

    if result == 0:
        status = "open"
    # Windows 的返回码和 Linux 不同，所以两组都收
    elif result in CLOSED_CODES:
        status = "closed"
    elif result in TIMEOUT_CODES:
        status = "timeout"
    else:
        status = "other"
    return {"port": port, "status": status, "code": result}


def save_result(result, target):
    """
    result:接收scan_ports返回的字典
    target:接收用户输入的ip
    将扫描结果存成json文件并生成新目录"output"(如已存在就不会创建)
    返回文件路径
    """
    filename = make_filename(target)

    os.makedirs("output", exist_ok=True)

    filepath = os.path.join("output", filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return filepath


def worker(target, port_queue, buckets, lock):
    """
    一个线程的工作：不断从队列取端口扫描，直到队列空
    """
    while True:
        try:
            port = port_queue.get_nowait()      # ⭐ 非阻塞取，取不到立刻抛异常
        except queue.Empty:
            return                              # ⭐ 队列空了 → 这个线程收工

        r = scan_port(target, port)

        if r["status"] in buckets:
            with lock:                          # ⭐ 加锁
                buckets[r["status"]].append(r["port"])


def scan_ports(target, ports, threads=50):
    """
    扫描一批端口，按状态分类返回。（多线程版）
    threads: 开几个线程
    """
    buckets = {"open": [], "closed": [], "timeout": []}

    # ① 所有端口入队
    port_queue = queue.Queue()
    for p in ports:
        port_queue.put(p)

    lock = threading.Lock()

    # ② 开 threads 个线程，全部启动
    workers = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(target, port_queue, buckets, lock))
        t.start()
        workers.append(t)

    # ③ 主线程等它们全部结束
    for t in workers:
        t.join()

    buckets["target"] = target
    buckets["ports"]  = list(ports)
    return buckets


def main():
    """
    命令行入口：从 sys.argv 取 IP 和端口范围，扫描后打印状态摘要。

    用法: python3 scan.py <目标IP> <起始端口> <结束端口>
    """
    if len(sys.argv)<4:
        print("用法:python3 scan.py 需扫描的ip 端口范围1 端口范围2")
        print("如需只扫描一个端口就填同一个数")
        print("空格不能省略！！！")
        sys.exit(1)

    target = sys.argv[1]

    try:
        start = int(sys.argv[2])
        end = int(sys.argv[3])
    except ValueError:
        print("端口号必须是数字")
        sys.exit(1)

    result = scan_ports(target, range(start, end + 1))
    fliepath = save_result(result, target)
    print("开放：", result["open"])
    print("关闭数：", len(result["closed"]))
    print("超时数：", len(result["timeout"]))
    print(f"结果已保存到：{fliepath}")


if __name__ == '__main__':
    main()