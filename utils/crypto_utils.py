"""
加密工具类
提供统一的加密解密接口
"""
import base64
import binascii


class CryptoUtils:
    """加密工具类"""
    
    @staticmethod
    def string_to_bytes(data, encoding='utf-8'):
        """字符串转字节"""
        if isinstance(data, str):
            return data.encode(encoding)
        return data
    
    @staticmethod
    def bytes_to_string(data, encoding='utf-8'):
        """字节转字符串"""
        if isinstance(data, bytes):
            return data.decode(encoding)
        return data
    
    @staticmethod
    def hex_to_bytes(hex_str):
        """十六进制字符串转字节"""
        return bytes.fromhex(hex_str)
    
    @staticmethod
    def bytes_to_hex(data):
        """字节转十六进制字符串"""
        return data.hex()
    
    @staticmethod
    def base64_to_bytes(b64_str):
        """Base64字符串转字节"""
        return base64.b64decode(b64_str)
    
    @staticmethod
    def bytes_to_base64(data):
        """字节转Base64字符串"""
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def detect_encoding(data):
        """检测数据编码"""
        if isinstance(data, bytes):
            try:
                data.decode('utf-8')
                return 'utf-8'
            except UnicodeDecodeError:
                try:
                    data.decode('gbk')
                    return 'gbk'
                except UnicodeDecodeError:
                    return 'binary'
        elif isinstance(data, str):
            return 'string'
        return 'unknown'
    
    @staticmethod
    def is_base64(data):
        """检查是否为Base64编码"""
        try:
            if isinstance(data, str):
                base64.b64decode(data)
                return True
        except Exception:
            pass
        return False
    
    @staticmethod
    def is_hex(data):
        """检查是否为十六进制编码"""
        try:
            if isinstance(data, str):
                bytes.fromhex(data)
                return True
        except (ValueError, binascii.Error):
            pass
        return False
    
    @staticmethod
    def convert_format(data, from_format, to_format):
        """
        转换数据格式
        
        Args:
            data: 输入数据
            from_format: 源格式 (string/hex/base64/bytes)
            to_format: 目标格式 (string/hex/base64/bytes)
            
        Returns:
            转换后的数据
        """
        # 先转换为bytes
        if from_format == 'string':
            data_bytes = data.encode('utf-8')
        elif from_format == 'hex':
            data_bytes = bytes.fromhex(data)
        elif from_format == 'base64':
            data_bytes = base64.b64decode(data)
        elif from_format == 'bytes':
            data_bytes = data
        else:
            raise ValueError(f"不支持的源格式: {from_format}")
        
        # 再转换为目标格式
        if to_format == 'string':
            return data_bytes.decode('utf-8')
        elif to_format == 'hex':
            return data_bytes.hex()
        elif to_format == 'base64':
            return base64.b64encode(data_bytes).decode('utf-8')
        elif to_format == 'bytes':
            return data_bytes
        else:
            raise ValueError(f"不支持的目标格式: {to_format}")
    
    @staticmethod
    def generate_random_bytes(length):
        """生成随机字节"""
        import os
        return os.urandom(length)
    
    @staticmethod
    def generate_random_hex(length):
        """生成随机十六进制字符串"""
        return CryptoUtils.generate_random_bytes(length).hex()
    
    @staticmethod
    def generate_random_base64(length):
        """生成随机Base64字符串"""
        return base64.b64encode(CryptoUtils.generate_random_bytes(length)).decode('utf-8')
