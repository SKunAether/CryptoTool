"""
AES加密解密模块
支持ECB, CBC, CTR, GCM等模式
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64


class AESCipher:
    """AES加密解密类"""
    
    MODES = {
        'ECB': AES.MODE_ECB,
        'CBC': AES.MODE_CBC,
        'CTR': AES.MODE_CTR,
        'GCM': AES.MODE_GCM,
        'CFB': AES.MODE_CFB,
        'OFB': AES.MODE_OFB
    }
    
    KEY_SIZES = [16, 24, 32]  # AES-128, AES-192, AES-256
    
    def __init__(self, key=None, mode='CBC', iv=None):
        """
        初始化AES加密器
        
        Args:
            key: 密钥，长度应为16/24/32字节
            mode: 加密模式
            iv: 初始化向量
        """
        self.key = key if key else get_random_bytes(16)
        self.mode = mode.upper()
        self.iv = iv
        
        if self.mode not in self.MODES:
            raise ValueError(f"不支持的模式: {self.mode}")
        
        if len(self.key) not in self.KEY_SIZES:
            raise ValueError(f"密钥长度必须为{self.KEY_SIZES}字节")
    
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
            cipher = AES.new(self.key, self.MODES[self.mode])
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        elif self.mode == 'CBC':
            if self.iv is None:
                self.iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self.key, self.MODES[self.mode], self.iv)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        elif self.mode == 'CTR':
            if self.iv is None:
                self.iv = get_random_bytes(8)
            cipher = AES.new(self.key, self.MODES[self.mode], nonce=self.iv)
            ciphertext = cipher.encrypt(plaintext)
        elif self.mode == 'GCM':
            if self.iv is None:
                self.iv = get_random_bytes(12)
            cipher = AES.new(self.key, self.MODES[self.mode], nonce=self.iv)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            ciphertext = tag + ciphertext
        elif self.mode in ['CFB', 'OFB']:
            if self.iv is None:
                self.iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self.key, self.MODES[self.mode], iv=self.iv)
            ciphertext = cipher.encrypt(plaintext)
        else:
            cipher = AES.new(self.key, self.MODES[self.mode])
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        
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
            cipher = AES.new(self.key, self.MODES[self.mode])
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        elif self.mode == 'CBC':
            if self.iv is None:
                raise ValueError("CBC模式需要提供IV")
            cipher = AES.new(self.key, self.MODES[self.mode], self.iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        elif self.mode == 'CTR':
            if self.iv is None:
                raise ValueError("CTR模式需要提供nonce")
            cipher = AES.new(self.key, self.MODES[self.mode], nonce=self.iv)
            plaintext = cipher.decrypt(ciphertext)
        elif self.mode == 'GCM':
            if self.iv is None:
                raise ValueError("GCM模式需要提供nonce")
            tag = ciphertext[:16]
            ciphertext = ciphertext[16:]
            cipher = AES.new(self.key, self.MODES[self.mode], nonce=self.iv)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        elif self.mode in ['CFB', 'OFB']:
            if self.iv is None:
                raise ValueError(f"{self.mode}模式需要提供IV")
            cipher = AES.new(self.key, self.MODES[self.mode], iv=self.iv)
            plaintext = cipher.decrypt(ciphertext)
        else:
            cipher = AES.new(self.key, self.MODES[self.mode])
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        return plaintext.decode('utf-8')
    
    @staticmethod
    def generate_key(size=16):
        """生成随机密钥"""
        return get_random_bytes(size)
    
    @staticmethod
    def generate_iv(size=16):
        """生成随机IV"""
        return get_random_bytes(size)
