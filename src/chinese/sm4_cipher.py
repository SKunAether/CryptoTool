"""
SM4分组密码算法模块
基于gmssl库实现
"""
import base64
try:
    from gmssl import sm4 as gmssl_sm4
    HAS_GMSSL = True
except ImportError:
    HAS_GMSSL = False
    print("警告: gmssl库未安装，SM4功能不可用")


class SM4Cipher:
    """SM4加密解密类"""
    
    MODES = ['ECB', 'CBC']
    
    def __init__(self, key=None, mode='ECB', iv=None):
        """
        初始化SM4加密器
        
        Args:
            key: 密钥（16字节）
            mode: 加密模式
            iv: 初始化向量（CBC模式需要）
        """
        if not HAS_GMSSL:
            raise ImportError("需要安装gmssl库: pip install gmssl")
        
        self.key = key if key else self.generate_key()
        self.mode = mode.upper()
        self.iv = iv
        
        if isinstance(self.key, str):
            self.key = bytes.fromhex(self.key)
        
        if len(self.key) != 16:
            raise ValueError("SM4密钥长度必须为16字节")
        
        self.sm4_crypt = gmssl_sm4.CryptSM4()
        self.sm4_crypt.set_key(self.key, gmssl_sm4.SM4_ENCRYPT)
    
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
        
        # 填充到16字节的倍数
        padding_length = 16 - (len(plaintext) % 16)
        plaintext += bytes([padding_length]) * padding_length
        
        if self.mode == 'ECB':
            ciphertext = self.sm4_crypt.crypt_ecb(plaintext)
        elif self.mode == 'CBC':
            if self.iv is None:
                self.iv = self.generate_iv()
            if isinstance(self.iv, str):
                self.iv = bytes.fromhex(self.iv)
            ciphertext = self.sm4_crypt.crypt_cbc(self.iv, plaintext)
        else:
            raise ValueError(f"不支持的模式: {self.mode}")
        
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
        
        self.sm4_crypt.set_key(self.key, gmssl_sm4.SM4_DECRYPT)
        
        if self.mode == 'ECB':
            plaintext = self.sm4_crypt.crypt_ecb(ciphertext)
        elif self.mode == 'CBC':
            if self.iv is None:
                raise ValueError("CBC模式需要提供IV")
            if isinstance(self.iv, str):
                self.iv = bytes.fromhex(self.iv)
            plaintext = self.sm4_crypt.crypt_cbc(self.iv, ciphertext)
        else:
            raise ValueError(f"不支持的模式: {self.mode}")
        
        # 去除填充
        padding_length = plaintext[-1]
        plaintext = plaintext[:-padding_length]
        
        return plaintext.decode('utf-8')
    
    @staticmethod
    def generate_key():
        """生成随机密钥"""
        import os
        return os.urandom(16)
    
    @staticmethod
    def generate_iv():
        """生成随机IV"""
        import os
        return os.urandom(16)
