#!/usr/bin/env python3
"""
Burp Suite扩展 - CryptoTool集成
通过REST API与独立CryptoTool工具通信
"""

# 注意：这是一个Python版本的Burp扩展概念代码
# 实际的Burp扩展需要使用Java编写，通过Burp Extender API
# 这里提供一个Python的REST API服务器，供Burp扩展调用

import json
import sys
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

# 添加项目目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.symmetric import AESCipher, DESCipher, RC4Cipher, TripleDESCipher
from src.asymmetric import RSACipher, ECCCipher
from src.digest import HashAlgorithms, HMACAlgorithms
from src.encoding import BaseEncodings, URLEncoding, HTMLEncoding


class CryptoAPIHandler(BaseHTTPRequestHandler):
    """加密API请求处理器"""
    
    def do_POST(self):
        """处理POST请求"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
            result = self.process_request(data)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
        except Exception as e:
            self.send_error(500, str(e))
    
    def do_OPTIONS(self):
        """处理OPTIONS请求（CORS预检）"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def process_request(self, data):
        """处理加密请求"""
        action = data.get('action', 'encrypt')
        algorithm = data.get('algorithm', 'AES')
        input_data = data.get('input', '')
        key = data.get('key', '')
        mode = data.get('mode', 'CBC')
        output_format = data.get('format', 'base64')
        
        if not input_data:
            return {'error': '输入数据为空'}
        
        try:
            result = self.execute_crypto(action, algorithm, mode, input_data, key, output_format)
            return {'success': True, 'result': result}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def execute_crypto(self, action, algorithm, mode, input_data, key, output_format):
        """执行加解密操作"""
        key_bytes = key.encode('utf-8') if key else None
        
        if algorithm == 'AES':
            cipher = AESCipher(key=key_bytes, mode=mode)
            if action == 'encrypt':
                return cipher.encrypt(input_data, output_format)
            else:
                return cipher.decrypt(input_data, output_format)
        
        elif algorithm == 'DES':
            cipher = DESCipher(key=key_bytes, mode=mode)
            if action == 'encrypt':
                return cipher.encrypt(input_data, output_format)
            else:
                return cipher.decrypt(input_data, output_format)
        
        elif algorithm == '3DES':
            cipher = TripleDESCipher(key=key_bytes, mode=mode)
            if action == 'encrypt':
                return cipher.encrypt(input_data, output_format)
            else:
                return cipher.decrypt(input_data, output_format)
        
        elif algorithm == 'RC4':
            cipher = RC4Cipher(key=key_bytes)
            if action == 'encrypt':
                return cipher.encrypt(input_data, output_format)
            else:
                return cipher.decrypt(input_data, output_format)
        
        elif algorithm == 'RSA':
            cipher = RSACipher(key=key)
            if action == 'encrypt':
                return cipher.encrypt(input_data, output_format)
            else:
                return cipher.decrypt(input_data, output_format)
        
        elif algorithm == 'Base64':
            if action == 'encrypt':
                return BaseEncodings.base64_encode(input_data)
            else:
                return BaseEncodings.base64_decode(input_data)
        
        elif algorithm == 'URL':
            if action == 'encrypt':
                return URLEncoding.encode(input_data)
            else:
                return URLEncoding.decode(input_data)
        
        elif algorithm == 'MD5':
            hash_algo = HashAlgorithms('MD5')
            return hash_algo.hash(input_data, output_format)
        
        elif algorithm == 'SHA256':
            hash_algo = HashAlgorithms('SHA256')
            return hash_algo.hash(input_data, output_format)
        
        else:
            return f'不支持的算法: {algorithm}'
    
    def log_message(self, format, *args):
        """自定义日志格式"""
        print(f"[CryptoAPI] {format % args}")


class CryptoAPIServer:
    """加密API服务器"""
    
    def __init__(self, host='127.0.0.1', port=8888):
        """
        初始化API服务器
        
        Args:
            host: 监听地址
            port: 监听端口
        """
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
    
    def start(self):
        """启动服务器"""
        self.server = HTTPServer((self.host, self.port), CryptoAPIHandler)
        print(f"[*] CryptoAPI服务器已启动: http://{self.host}:{self.port}")
        print(f"[*] 支持的API端点: POST /")
        print(f"[*] 请求格式: {{'action': 'encrypt/decrypt', 'algorithm': 'AES', 'input': 'data', 'key': 'key'}}")
        
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        """停止服务器"""
        if self.server:
            self.server.shutdown()
            print("[*] CryptoAPI服务器已停止")


def main():
    """主函数"""
    print("=" * 50)
    print("  CryptoTool API Server for Burp Suite")
    print("=" * 50)
    
    server = CryptoAPIServer(host='127.0.0.1', port=8888)
    
    try:
        server.start()
        print("\n[*] 按Ctrl+C停止服务器...")
        
        # 保持主线程运行
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 正在停止服务器...")
        server.stop()


if __name__ == '__main__':
    main()
