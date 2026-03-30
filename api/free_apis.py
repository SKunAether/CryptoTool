"""
免费在线加解密API客户端
"""
import requests
import json
import hashlib
import base64
from urllib.parse import quote, unquote


class FreeAPIClient:
    """免费API客户端"""
    
    def __init__(self, timeout=10):
        """
        初始化API客户端
        
        Args:
            timeout: 请求超时时间（秒）
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def base64_encode(self, text):
        """Base64编码"""
        try:
            response = self.session.get(
                'https://v2.xxapi.cn/api/base64',
                params={'type': 'encode', 'text': text},
                timeout=self.timeout
            )
            data = response.json()
            if data.get('code') == 200 and data.get('data'):
                return data.get('data', '')
        except:
            pass
        
        # 本地计算
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')
    
    def base64_decode(self, text):
        """Base64解码"""
        try:
            response = self.session.get(
                'https://v2.xxapi.cn/api/base64',
                params={'type': 'decode', 'text': text},
                timeout=self.timeout
            )
            data = response.json()
            if data.get('code') == 200 and data.get('data'):
                return data.get('data', '')
        except:
            pass
        
        # 本地计算
        return base64.b64decode(text).decode('utf-8')
    
    def md5(self, text):
        """MD5加密"""
        try:
            response = self.session.get(
                'https://api.hashify.net/hash/md5/hex',
                params={'value': text},
                timeout=self.timeout
            )
            data = response.json()
            if 'Digest' in data:
                return data['Digest']
        except:
            pass
        
        # 本地计算
        return hashlib.md5(text.encode('utf-8')).hexdigest()
    
    def sha1(self, text):
        """SHA1加密"""
        try:
            response = self.session.get(
                'https://api.hashify.net/hash/sha1/hex',
                params={'value': text},
                timeout=self.timeout
            )
            data = response.json()
            if 'Digest' in data:
                return data['Digest']
        except:
            pass
        
        return hashlib.sha1(text.encode('utf-8')).hexdigest()
    
    def sha256(self, text):
        """SHA256加密"""
        try:
            response = self.session.get(
                'https://api.hashify.net/hash/sha256/hex',
                params={'value': text},
                timeout=self.timeout
            )
            data = response.json()
            if 'Digest' in data:
                return data['Digest']
        except:
            pass
        
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
    
    def sha512(self, text):
        """SHA512加密"""
        try:
            response = self.session.get(
                'https://api.hashify.net/hash/sha512/hex',
                params={'value': text},
                timeout=self.timeout
            )
            data = response.json()
            if 'Digest' in data:
                return data['Digest']
        except:
            pass
        
        return hashlib.sha512(text.encode('utf-8')).hexdigest()
    
    def url_encode(self, text):
        """URL编码"""
        return quote(text)
    
    def url_decode(self, text):
        """URL解码"""
        return unquote(text)
    
    def call_api(self, api_name, input_data):
        """
        调用API
        
        Args:
            api_name: API名称
            input_data: 输入数据
            
        Returns:
            API返回结果
        """
        methods = {
            'base64_encode': self.base64_encode,
            'base64_decode': self.base64_decode,
            'md5': self.md5,
            'sha1': self.sha1,
            'sha256': self.sha256,
            'sha512': self.sha512,
            'url_encode': self.url_encode,
            'url_decode': self.url_decode
        }
        
        if api_name in methods:
            return methods[api_name](input_data)
        else:
            raise ValueError(f"未知的API: {api_name}")
    
    def get_supported_apis(self):
        """获取支持的API列表"""
        return {
            'base64_encode': 'Base64编码',
            'base64_decode': 'Base64解码',
            'md5': 'MD5加密',
            'sha1': 'SHA1加密',
            'sha256': 'SHA256加密',
            'sha512': 'SHA512加密',
            'url_encode': 'URL编码',
            'url_decode': 'URL解码'
        }
