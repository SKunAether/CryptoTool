"""
3DES加密解密模块
"""
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


class TripleDESCipher:
    """3DES加密解密类"""
    
    MODES = {
        'ECB': DES3.MODE_ECB,
        'CBC': DES3.MODE_CBC
    }
    
    def __init__(self, key=None, mode='CBC', iv=None):
        """
        初始化3DES加密器
        
        Args:
            key: 密钥，长度应为16或24字节
            mode: 加密模式
            iv: 初始化向量
        """
        self.key = key if key else DES3.adjust_key_parity(get_random_bytes(24))
        self.mode = mode.upper()
        self.iv = iv
        
        if self.mode not in self.MODES:
            raise ValueError(f"不支持的模式: {self.mode}")
        
        if len(self.key) not in [16, 24]:
            raise ValueError("3DES密钥长度必须为16或24字节")
        
        self.key = DES3.adjust_key_parity(self.key)
    
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
            cipher = DES3.new(self.key, self.MODES[self.mode])
            ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))
        elif self.mode == 'CBC':
            if self.iv is None:
                self.iv = get_random_bytes(DES3.block_size)
            cipher = DES3.new(self.key, self.MODES[self.mode], self.iv)
            ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))
        
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
            cipher = DES3.new(self.key, self.MODES[self.mode])
            plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
        elif self.mode == 'CBC':
            if self.iv is None:
                raise ValueError("CBC模式需要提供IV")
            cipher = DES3.new(self.key, self.MODES[self.mode], self.iv)
            plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
        
        return plaintext.decode('utf-8')
    
    @staticmethod
    def generate_key(size=24):
        """生成随机密钥"""
        return DES3.adjust_key_parity(get_random_bytes(size))
    
    @staticmethod
    def generate_iv():
        """生成随机IV"""
        return get_random_bytes(DES3.block_size)
