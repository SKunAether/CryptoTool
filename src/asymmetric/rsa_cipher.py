"""
RSA加密解密模块
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64


class RSACipher:
    """RSA加密解密类"""
    
    PADDING_TYPES = {
        'PKCS1_v1_5': PKCS1_v1_5,
        'OAEP': PKCS1_OAEP
    }
    
    def __init__(self, key=None, key_size=2048, padding='OAEP'):
        """
        初始化RSA加密器
        
        Args:
            key: 密钥对象或PEM格式密钥
            key_size: 密钥长度
            padding: 填充方式
        """
        self.key_size = key_size
        self.padding = padding
        
        if key is None:
            self.key = RSA.generate(key_size)
        elif isinstance(key, str):
            self.key = RSA.import_key(key)
        else:
            self.key = key
        
        self.public_key = self.key.publickey()
    
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
        
        if self.padding == 'OAEP':
            cipher = PKCS1_OAEP.new(self.public_key)
        else:
            cipher = PKCS1_v1_5.new(self.public_key)
        
        # RSA加密有长度限制，需要分块处理
        key_size = self.key_size // 8
        chunk_size = key_size - 42 if self.padding == 'OAEP' else key_size - 11
        
        ciphertext = b''
        for i in range(0, len(plaintext), chunk_size):
            chunk = plaintext[i:i + chunk_size]
            ciphertext += cipher.encrypt(chunk)
        
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
        
        if self.padding == 'OAEP':
            cipher = PKCS1_OAEP.new(self.key)
        else:
            cipher = PKCS1_v1_5.new(self.key)
        
        # 分块解密
        key_size = self.key_size // 8
        plaintext = b''
        for i in range(0, len(ciphertext), key_size):
            chunk = ciphertext[i:i + key_size]
            plaintext += cipher.decrypt(chunk)
        
        return plaintext.decode('utf-8')
    
    def sign(self, message, hash_algo=SHA256):
        """
        数字签名
        
        Args:
            message: 待签名消息
            hash_algo: 哈希算法
            
        Returns:
            签名数据
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        h = hash_algo.new(message)
        signature = pkcs1_15.new(self.key).sign(h)
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify(self, message, signature, hash_algo=SHA256):
        """
        验证签名
        
        Args:
            message: 原始消息
            signature: 签名数据
            hash_algo: 哈希算法
            
        Returns:
            验证结果
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        signature = base64.b64decode(signature)
        h = hash_algo.new(message)
        
        try:
            pkcs1_15.new(self.public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    
    def export_public_key(self, format='PEM'):
        """导出公钥"""
        return self.public_key.export_key(format=format).decode('utf-8')
    
    def export_private_key(self, format='PEM'):
        """导出私钥"""
        return self.key.export_key(format=format).decode('utf-8')
    
    @staticmethod
    def generate_key_pair(key_size=2048):
        """生成密钥对"""
        key = RSA.generate(key_size)
        return key, key.publickey()
