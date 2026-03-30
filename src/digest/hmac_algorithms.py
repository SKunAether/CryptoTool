"""
HMAC算法模块
"""
import hashlib
import hmac


class HMACAlgorithms:
    """HMAC算法类"""
    
    ALGORITHMS = {
        'MD5': hashlib.md5,
        'SHA1': hashlib.sha1,
        'SHA256': hashlib.sha256,
        'SHA384': hashlib.sha384,
        'SHA512': hashlib.sha512
    }
    
    def __init__(self, key, algorithm='SHA256'):
        """
        初始化HMAC算法
        
        Args:
            key: 密钥
            algorithm: 算法名称
        """
        self.key = key if isinstance(key, bytes) else key.encode('utf-8')
        self.algorithm = algorithm.upper()
        
        if self.algorithm not in self.ALGORITHMS:
            raise ValueError(f"不支持的算法: {self.algorithm}")
    
    def sign(self, message, output_format='hex'):
        """
        生成HMAC签名
        
        Args:
            message: 消息内容
            output_format: 输出格式 (hex/base64)
            
        Returns:
            HMAC签名
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        h = hmac.new(self.key, message, self.ALGORITHMS[self.algorithm])
        
        if output_format == 'hex':
            return h.hexdigest()
        elif output_format == 'base64':
            import base64
            return base64.b64encode(h.digest()).decode('utf-8')
        else:
            return h.digest()
    
    def verify(self, message, signature, input_format='hex'):
        """
        验证HMAC签名
        
        Args:
            message: 消息内容
            signature: 签名
            input_format: 输入格式 (hex/base64)
            
        Returns:
            验证结果
        """
        expected = self.sign(message, input_format)
        return hmac.compare_digest(expected, signature)
    
    @staticmethod
    def get_supported_algorithms():
        """获取支持的算法列表"""
        return list(HMACAlgorithms.ALGORITHMS.keys())
