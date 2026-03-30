"""
SM3密码杂凑算法模块
基于gmssl库实现
"""
import base64
try:
    from gmssl import sm3 as gmssl_sm3
    HAS_GMSSL = True
except ImportError:
    HAS_GMSSL = False
    print("警告: gmssl库未安装，SM3功能不可用")


class SM3Hash:
    """SM3哈希算法类"""
    
    def __init__(self):
        """初始化SM3哈希算法"""
        if not HAS_GMSSL:
            raise ImportError("需要安装gmssl库: pip install gmssl")
    
    def hash(self, data, output_format='hex'):
        """
        计算SM3哈希值
        
        Args:
            data: 输入数据
            output_format: 输出格式 (hex/base64)
            
        Returns:
            哈希值
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # 转换为整数列表
        data_list = list(data)
        
        # 计算哈希值
        hash_hex = gmssl_sm3.sm3_hash(data_list)
        
        if output_format == 'hex':
            return hash_hex
        elif output_format == 'base64':
            hash_bytes = bytes.fromhex(hash_hex)
            return base64.b64encode(hash_bytes).decode('utf-8')
        else:
            return bytes.fromhex(hash_hex)
    
    def hash_file(self, filepath, output_format='hex', chunk_size=8192):
        """
        计算文件SM3哈希值
        
        Args:
            filepath: 文件路径
            output_format: 输出格式
            chunk_size: 分块大小
            
        Returns:
            哈希值
        """
        import hashlib
        
        # 使用Python实现计算文件哈希
        h = hashlib.new('sm3')
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        
        hash_hex = h.hexdigest()
        
        if output_format == 'hex':
            return hash_hex
        elif output_format == 'base64':
            hash_bytes = bytes.fromhex(hash_hex)
            return base64.b64encode(hash_bytes).decode('utf-8')
        else:
            return bytes.fromhex(hash_hex)
