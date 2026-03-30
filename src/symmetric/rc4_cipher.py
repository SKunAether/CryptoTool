"""
RC4加密解密模块
"""
from Crypto.Cipher import ARC4
import base64


class RC4Cipher:
    """RC4加密解密类"""
    
    def __init__(self, key=None):
        """
        初始化RC4加密器
        
        Args:
            key: 密钥
        """
        self.key = key if key else b'default_key'
        
        if isinstance(self.key, str):
            self.key = self.key.encode('utf-8')
    
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
        
        cipher = ARC4.new(self.key)
        ciphertext = cipher.encrypt(plaintext)
        
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
        
        cipher = ARC4.new(self.key)
        plaintext = cipher.decrypt(ciphertext)
        
        return plaintext.decode('utf-8')
