"""
自定义API客户端
支持配置任意加解密API端点
"""
import requests
import json
import re


class CustomAPIClient:
    """自定义API客户端"""
    
    def __init__(self, base_url=None, headers=None, timeout=10):
        """
        初始化自定义API客户端
        
        Args:
            base_url: API基础URL
            headers: 请求头
            timeout: 超时时间
        """
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        
        if headers:
            self.session.headers.update(headers)
        
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'CryptoTool/1.0'
        })
    
    def set_base_url(self, url):
        """设置基础URL"""
        self.base_url = url.rstrip('/')
    
    def add_header(self, key, value):
        """添加请求头"""
        self.session.headers[key] = value
    
    def call(self, endpoint, method='POST', data=None, params=None):
        """
        调用API
        
        Args:
            endpoint: API端点（相对于base_url的路径）
            method: 请求方法
            data: 请求体数据
            params: URL参数
            
        Returns:
            API返回结果
        """
        if self.base_url:
            url = f"{self.base_url}/{endpoint.lstrip('/')}"
        else:
            url = endpoint
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=self.timeout)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, params=params, timeout=self.timeout)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data, params=params, timeout=self.timeout)
            else:
                response = self.session.request(method, url, json=data, params=params, timeout=self.timeout)
            
            response.raise_for_status()
            
            # 尝试解析JSON
            try:
                return response.json()
            except json.JSONDecodeError:
                return response.text
        
        except requests.exceptions.RequestException as e:
            raise Exception(f"API请求失败: {str(e)}")
    
    def encrypt(self, algorithm, data, key=None, mode=None, **kwargs):
        """
        调用加密API
        
        Args:
            algorithm: 加密算法
            data: 待加密数据
            key: 密钥
            mode: 加密模式
            **kwargs: 其他参数
            
        Returns:
            加密结果
        """
        payload = {
            'action': 'encrypt',
            'algorithm': algorithm,
            'data': data,
            **kwargs
        }
        
        if key:
            payload['key'] = key
        if mode:
            payload['mode'] = mode
        
        return self.call('', method='POST', data=payload)
    
    def decrypt(self, algorithm, data, key=None, mode=None, **kwargs):
        """
        调用解密API
        
        Args:
            algorithm: 加密算法
            data: 待解密数据
            key: 密钥
            mode: 加密模式
            **kwargs: 其他参数
            
        Returns:
            解密结果
        """
        payload = {
            'action': 'decrypt',
            'algorithm': algorithm,
            'data': data,
            **kwargs
        }
        
        if key:
            payload['key'] = key
        if mode:
            payload['mode'] = mode
        
        return self.call('', method='POST', data=payload)
    
    def hash(self, algorithm, data, **kwargs):
        """
        调用哈希API
        
        Args:
            algorithm: 哈希算法
            data: 待哈希数据
            **kwargs: 其他参数
            
        Returns:
            哈希结果
        """
        payload = {
            'action': 'hash',
            'algorithm': algorithm,
            'data': data,
            **kwargs
        }
        
        return self.call('', method='POST', data=payload)
    
    def test_connection(self):
        """
        测试API连接
        
        Returns:
            测试结果
        """
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            return {'success': True, 'status_code': response.status_code}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def parse_response(response, key_path=None):
        """
        解析API响应
        
        Args:
            response: API响应
            key_path: 键路径（如 'data.result'）
            
        Returns:
            解析结果
        """
        if not key_path:
            return response
        
        if isinstance(response, str):
            try:
                response = json.loads(response)
            except json.JSONDecodeError:
                return response
        
        keys = key_path.split('.')
        result = response
        
        for key in keys:
            if isinstance(result, dict) and key in result:
                result = result[key]
            else:
                return None
        
        return result
