import socket
import threading
import select
import os

PORT = int(os.environ.get('SERVER_PORT', os.environ.get('PORT', 20006)))

# ================= 账号密码配置 =================
AUTH_USER = "opsmk"
AUTH_PASS = "ABcd1234"
# ===============================================

def handle_client(client_sock, client_addr):
    print(f"[+] 收到客户端连接: {client_addr}")
    remote_sock = None
    try:
        # 1. SOCKS5 握手阶段 1: 协商认证方式
        header = client_sock.recv(2)
        if len(header) < 2 or header[0] != 0x05:
            client_sock.close()
            return
        
        nmethods = header[1]
        methods = client_sock.recv(nmethods)
        
        # 要求使用用户名密码认证 (0x02)，如果客户端不支持则退化为无认证 (0x00)
        # 这里为了安全，强制要求 0x02 认证，或者允许 0x00
        if 0x02 in methods:
            # 告诉客户端：选择用户名密码认证
            client_sock.sendall(b"\x05\x02")
            
            # 2. SOCKS5 用户名密码认证子协议 (RFC 1929)
            sub_ver = client_sock.recv(1)
            if not sub_ver or sub_ver[0] != 0x01:
                client_sock.close()
                return
                
            ulen = client_sock.recv(1)[0]
            user = client_sock.recv(ulen).decode('utf-8', errors='ignore')
            plen = client_sock.recv(1)[0]
            passwd = client_sock.recv(plen).decode('utf-8', errors='ignore')
            
            if user == AUTH_USER and passwd == AUTH_PASS:
                # 认证成功
                client_sock.sendall(b"\x01\x00")
            else:
                # 认证失败
                client_sock.sendall(b"\x01\x01")
                client_sock.close()
                print(f"[-] SOCKS5 认证失败: user={user}")
                return
        else:
            # 不要求认证直接过 (根据需要开启)
            client_sock.sendall(b"\x05\x00")

        # 3. SOCKS5 请求阶段：解析目标地址
        req = client_sock.recv(4)
        if len(req) < 4 or req[0] != 0x05 or req[1] != 0x01: # 0x01 代表 CONNECT 请求
            client_sock.close()
            return

        atyp = req[3]
        if atyp == 0x01: # IPv4
            target_host = socket.inet_ntoa(client_sock.recv(4))
        elif atyp == 0x03: # 域名
            addr_len = client_sock.recv(1)[0]
            target_host = client_sock.recv(addr_len).decode('utf-8', errors='ignore')
        elif atyp == 0x04: # IPv6
            target_host = socket.inet_ntop(socket.AF_INET6, client_sock.recv(16))
        else:
            client_sock.close()
            return

        port_bytes = client_sock.recv(2)
        target_port = int.from_bytes(port_bytes, 'big')

        print(f"[->] 正在通过 SOCKS5 转发到目标: {target_host}:{target_port}")
        
        # 连接远端目标服务器
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.connect((target_host, target_port))

        # 4. 回复客户端 SOCKS5 连接建立成功
        # 0x00 表示成功，后面跟绑定地址和端口（这里简单返回 0 即可）
        reply = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        client_sock.sendall(reply)

        # 5. 双向流量转发 (TCP 管道)
        sockets = [client_sock, remote_sock]
        while True:
            r, w, e = select.select(sockets, [], [], 60)
            if not r:
                break
            if client_sock in r:
                data = client_sock.recv(4096)
                if not data:
                    break
                remote_sock.sendall(data)
            elif remote_sock in r:
                data = remote_sock.recv(4096)
                if not data:
                    break
                client_sock.sendall(data)

    except Exception as e:
        print(f"[!] 异常: {e}")
    finally:
        try:
            client_sock.close()
        except:
            pass
        if remote_sock:
            try:
                remote_sock.close()
            except:
                pass

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(128)
    print(f"====== SOCKS5 代理服务已启动，监听端口 {PORT} ======")
    
    while True:
        client_sock, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()

if __name__ == '__main__':
    main()