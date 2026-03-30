"""
Base编码模块
支持Base64, Base32, Base58, Base85
"""
import base64
import base58


class BaseEncodings:
    """Base编码类"""
    
    @staticmethod
    def base64_encode(data, url_safe=False):
        """
        Base64编码
        
        Args:
            data: 输入数据
            url_safe: 是否使用URL安全编码
            
        Returns:
            编码后的字符串
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if url_safe:
            return base64.urlsafe_b64encode(data).decode('utf-8')
        else:
            return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def base64_decode(data, url_safe=False):
        """
        Base64解码
        
        Args:
            data: 编码后的字符串
            url_safe: 是否使用URL安全编码
            
        Returns:
            解码后的数据
        """
        if url_safe:
            return base64.urlsafe_b64decode(data).decode('utf-8')
        else:
            return base64.b64decode(data).decode('utf-8')
    
    @staticmethod
    def base32_encode(data):
        """
        Base32编码
        
        Args:
            data: 输入数据
            
        Returns:
            编码后的字符串
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b32encode(data).decode('utf-8')
    
    @staticmethod
    def base32_decode(data):
        """
        Base32解码
        
        Args:
            data: 编码后的字符串
            
        Returns:
            解码后的数据
        """
        return base64.b32decode(data).decode('utf-8')
    
    @staticmethod
    def base58_encode(data):
        """
        Base58编码
        
        Args:
            data: 输入数据
            
        Returns:
            编码后的字符串
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base58.b58encode(data).decode('utf-8')
    
    @staticmethod
    def base58_decode(data):
        """
        Base58解码
        
        Args:
            data: 编码后的字符串
            
        Returns:
            解码后的数据
        """
        return base58.b58decode(data).decode('utf-8')
    
    @staticmethod
    def base85_encode(data):
        """
        Base85编码
        
        Args:
            data: 输入数据
            
        Returns:
            编码后的字符串
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b85encode(data).decode('utf-8')
    
    @staticmethod
    def base85_decode(data):
        """
        Base85解码
        
        Args:
            data: 编码后的字符串
            
        Returns:
            解码后的数据
        """
        return base64.b85decode(data).decode('utf-8')
