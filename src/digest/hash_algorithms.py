"""
哈希算法模块
支持MD5, SHA1, SHA224, SHA256, SHA384, SHA512, RIPEMD160
"""
import hashlib


class HashAlgorithms:
    """哈希算法类"""
    
    ALGORITHMS = {
        'MD5': hashlib.md5,
        'SHA1': hashlib.sha1,
        'SHA224': hashlib.sha224,
        'SHA256': hashlib.sha256,
        'SHA384': hashlib.sha384,
        'SHA512': hashlib.sha512,
        'SHA3_224': hashlib.sha3_224,
        'SHA3_256': hashlib.sha3_256,
        'SHA3_384': hashlib.sha3_384,
        'SHA3_512': hashlib.sha3_512,
        'RIPEMD160': hashlib.new('ripemd160')
    }
    
    def __init__(self, algorithm='SHA256'):
        """
        初始化哈希算法
        
        Args:
            algorithm: 算法名称
        """
        self.algorithm = algorithm.upper()
        if self.algorithm not in self.ALGORITHMS:
            raise ValueError(f"不支持的算法: {self.algorithm}")
    
    def hash(self, data, output_format='hex'):
        """
        计算哈希值
        
        Args:
            data: 输入数据
            output_format: 输出格式 (hex/base64)
            
        Returns:
            哈希值
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if self.algorithm == 'RIPEMD160':
            h = hashlib.new('ripemd160')
        else:
            h = self.ALGORITHMS[self.algorithm]()
        
        h.update(data)
        
        if output_format == 'hex':
            return h.hexdigest()
        elif output_format == 'base64':
            import base64
            return base64.b64encode(h.digest()).decode('utf-8')
        else:
            return h.digest()
    
    def hash_file(self, filepath, output_format='hex', chunk_size=8192):
        """
        计算文件哈希值
        
        Args:
            filepath: 文件路径
            output_format: 输出格式
            chunk_size: 分块大小
            
        Returns:
            哈希值
        """
        if self.algorithm == 'RIPEMD160':
            h = hashlib.new('ripemd160')
        else:
            h = self.ALGORITHMS[self.algorithm]()
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        
        if output_format == 'hex':
            return h.hexdigest()
        elif output_format == 'base64':
            import base64
            return base64.b64encode(h.digest()).decode('utf-8')
        else:
            return h.digest()
    
    @staticmethod
    def get_supported_algorithms():
        """获取支持的算法列表"""
        return list(HashAlgorithms.ALGORITHMS.keys())
