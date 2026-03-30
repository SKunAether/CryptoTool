"""
DES加密解密模块
"""
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


class DESCipher:
    """DES加密解密类"""
    
    MODES = {
        'ECB': DES.MODE_ECB,
        'CBC': DES.MODE_CBC
    }
    
    def __init__(self, key=None, mode='CBC', iv=None):
        """
        初始化DES加密器
        
        Args:
            key: 密钥，长度应为8字节
            mode: 加密模式
            iv: 初始化向量
        """
        self.key = key if key else get_random_bytes(8)
        self.mode = mode.upper()
        self.iv = iv
        
        if self.mode not in self.MODES:
            raise ValueError(f"不支持的模式: {self.mode}")
        
        if len(self.key) != 8:
            raise ValueError("DES密钥长度必须为8字节")
    
    def encrypt(self, plaintext, output_format='base64'):
        """
        加密数据
        
        Args:
            plaintext: 明文数据
            output_format: 输出格式 (base64/hex)
            
        Returns:
            加密后的数据
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        if self.mode == 'ECB':
            cipher = DES.new(self.key, self.MODES[self.mode])
            ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))
        elif self.mode == 'CBC':
            if self.iv is None:
                self.iv = get_random_bytes(DES.block_size)
            cipher = DES.new(self.key, self.MODES[self.mode], self.iv)
            ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))
        
        if output_format == 'base64':
            return base64.b64encode(ciphertext).decode('utf-8')
        elif output_format == 'hex':
            return ciphertext.hex()
        else:
            return ciphertext
    
    def decrypt(self, ciphertext, input_format='base64'):
        """
        解密数据
        
        Args:
            ciphertext: 密文数据
            input_format: 输入格式 (base64/hex)
            
        Returns:
            解密后的明文
        """
        if input_format == 'base64':
            ciphertext = base64.b64decode(ciphertext)
        elif input_format == 'hex':
            ciphertext = bytes.fromhex(ciphertext)
        
        if self.mode == 'ECB':
            cipher = DES.new(self.key, self.MODES[self.mode])
            plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
        elif self.mode == 'CBC':
            if self.iv is None:
                raise ValueError("CBC模式需要提供IV")
            cipher = DES.new(self.key, self.MODES[self.mode], self.iv)
            plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
        
        return plaintext.decode('utf-8')
    
    @staticmethod
    def generate_key():
        """生成随机密钥"""
        return get_random_bytes(8)
    
    @staticmethod
    def generate_iv():
        """生成随机IV"""
        return get_random_bytes(8)
