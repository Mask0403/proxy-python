import socket
import threading
import select
import base64
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
        # 读取 HTTP 请求头
        request_data = b""
        while b"\r\n\r\n" not in request_data:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            request_data += chunk
            if len(request_data) > 8192:
                break

        if not request_data:
            client_sock.close()
            return

        lines = request_data.split(b"\r\n")
        first_line = lines[0].decode('utf-8', errors='ignore')
        parts = first_line.split(" ")
        if len(parts) < 2:
            client_sock.close()
            return

        method, url = parts[0], parts[1]

        # 检查 Proxy-Authorization 认证
        authed = False
        expected_auth = base64.b64encode(f"{AUTH_USER}:{AUTH_PASS}".encode()).decode()
        for line in lines:
            if line.lower().startswith(b"proxy-authorization: basic "):
                token = line.split(b" ")[2].decode()
                if token == expected_auth:
                    authed = True
                    break

        if not authed:
            # 认证失败，返回 407 要求输入账号密码
            challenge = (
                "HTTP/1.1 407 Proxy Authentication Required\r\n"
                "Proxy-Authenticate: Basic realm=\"Proxy Required\"\r\n"
                "Content-Length: 0\r\n\r\n"
            )
            client_sock.sendall(challenge.encode())
            client_sock.close()
            return

        # 解析目标地址
        if method == "CONNECT":
            # HTTPS / 隧道代理
            host_port = url
            if ":" in host_port:
                target_host, target_port = host_port.split(":")
                target_port = int(target_port)
            else:
                target_host = host_port
                target_port = 443

            # 回复客户端 CONNECT 建立成功
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            # 普通 HTTP 代理
            if url.startswith("http://"):
                url = url[7:]
            if "/" in url:
                host_port, _ = url.split("/", 1)
            else:
                host_port = url
            
            if ":" in host_port:
                target_host, target_port = host_port.split(":")
                target_port = int(target_port)
            else:
                target_host = host_port
                target_port = 80

            # 把剩余的请求体转发给目标
            # 简化处理：对于普通 HTTP，把首行 URL 里的协议域名去掉
            # 实际生产中可以更完整，这里重点保证主干通畅

        print(f"[->] 正在转发到目标: {target_host}:{target_port}")
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.connect((target_host, target_port))

        # 如果是普通 HTTP 且带了剩余数据，可以转发，如果是 CONNECT 则直接开始双向流转发
        if method != "CONNECT":
            # 重新构造请求发给远端
            new_first_line = f"{method} {url} HTTP/1.1\r\n"
            # 过滤掉 Proxy 相关的头
            forward_data = new_first_line.encode() + b"\r\n".join([l for l in lines[1:] if not l.lower().startswith(b"proxy-")])
            remote_sock.sendall(forward_data)

        # 双向流量转发
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
    print(f"====== HTTP 代理服务已启动，监听端口 {PORT} ======")
    
    while True:
        client_sock, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True).start()

if __name__ == '__main__':
    main()