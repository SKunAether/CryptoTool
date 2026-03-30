"""
URL编码模块
"""
from urllib.parse import quote, unquote, quote_plus, unquote_plus


class URLEncoding:
    """URL编码类"""
    
    @staticmethod
    def encode(data, safe='/', plus=False):
        """
        URL编码
        
        Args:
            data: 输入数据
            safe: 安全字符
            plus: 是否使用+号编码空格
            
        Returns:
            编码后的字符串
        """
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        
        if plus:
            return quote_plus(data, safe=safe)
        else:
            return quote(data, safe=safe)
    
    @staticmethod
    def decode(data, plus=False):
        """
        URL解码
        
        Args:
            data: 编码后的字符串
            plus: 是否使用+号编码空格
            
        Returns:
            解码后的字符串
        """
        if plus:
            return unquote_plus(data)
        else:
            return unquote(data)
    
    @staticmethod
    def encode_component(data):
        """
        URL组件编码
        
        Args:
            data: 输入数据
            
        Returns:
            编码后的字符串
        """
        return quote(data, safe='')
    
    @staticmethod
    def decode_component(data):
        """
        URL组件解码
        
        Args:
            data: 编码后的字符串
            
        Returns:
            解码后的字符串
        """
        return unquote(data)
