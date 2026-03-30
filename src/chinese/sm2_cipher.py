"""
SM2椭圆曲线公钥密码算法模块
基于gmssl库实现
"""
import base64
try:
    from gmssl import sm2, func
    HAS_GMSSL = True
except ImportError:
    HAS_GMSSL = False
    print("警告: gmssl库未安装，SM2功能不可用")


class SM2Cipher:
    """SM2加密解密类"""
    
    def __init__(self, private_key=None, public_key=None):
        """
        初始化SM2加密器
        
        Args:
            private_key: 私钥（十六进制字符串）
            public_key: 公钥（十六进制字符串）
        """
        if not HAS_GMSSL:
            raise ImportError("需要安装gmssl库: pip install gmssl")
        
        if private_key is None and public_key is None:
            # 生成新的密钥对
            self.private_key, self.public_key = self.generate_key_pair()
        else:
            self.private_key = private_key
            self.public_key = public_key
        
        self.sm2_crypt = sm2.CryptSM2(
            private_key=self.private_key or '',
            public_key=self.public_key or ''
        )
    
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
        
        ciphertext = self.sm2_crypt.encrypt(plaintext)
        
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
        
        plaintext = self.sm2_crypt.decrypt(ciphertext)
        return plaintext.decode('utf-8')
    
    def sign(self, message):
        """
        数字签名
        
        Args:
            message: 待签名消息
            
        Returns:
            签名数据
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # 生成随机数
        random_hex = func.random_hex(self.sm2_crypt.para_len)
        signature = self.sm2_crypt.sign(message, random_hex)
        
        return signature
    
    def verify(self, message, signature):
        """
        验证签名
        
        Args:
            message: 原始消息
            signature: 签名数据
            
        Returns:
            验证结果
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        return self.sm2_crypt.verify(signature, message)
    
    def export_public_key(self):
        """导出公钥"""
        return self.public_key
    
    def export_private_key(self):
        """导出私钥"""
        return self.private_key
    
    @staticmethod
    def generate_key_pair():
        """生成密钥对"""
        if not HAS_GMSSL:
            raise ImportError("需要安装gmssl库: pip install gmssl")
        
        sm2_crypt = sm2.CryptSM2(private_key='', public_key='')
        private_key = sm2_crypt.generate_private_key()
        public_key = sm2_crypt.generate_public_key(private_key)
        
        return private_key, public_key
