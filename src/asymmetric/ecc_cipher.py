"""
ECC椭圆曲线加密模块
"""
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os


class ECCCipher:
    """ECC加密解密类"""
    
    CURVES = {
        'SECP256R1': ec.SECP256R1(),
        'SECP384R1': ec.SECP384R1(),
        'SECP521R1': ec.SECP521R1(),
        'SECP256K1': ec.SECP256K1()
    }
    
    def __init__(self, private_key=None, curve='SECP256R1'):
        """
        初始化ECC加密器
        
        Args:
            private_key: 私钥对象
            curve: 椭圆曲线类型
        """
        self.curve = self.CURVES.get(curve, ec.SECP256R1())
        
        if private_key is None:
            self.private_key = ec.generate_private_key(self.curve, default_backend())
        elif isinstance(private_key, str):
            self.private_key = serialization.load_pem_private_key(
                private_key.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
        else:
            self.private_key = private_key
        
        self.public_key = self.private_key.public_key()
    
    def encrypt(self, plaintext, output_format='base64'):
        """
        加密数据 (使用ECDH + AES)
        
        Args:
            plaintext: 明文数据
            output_format: 输出格式 (base64/hex)
            
        Returns:
            加密后的数据
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # 生成临时密钥对
        ephemeral_key = ec.generate_private_key(self.curve, default_backend())
        ephemeral_public = ephemeral_key.public_key()
        
        # ECDH密钥协商
        shared_key = ephemeral_key.exchange(ec.ECDH(), self.public_key)
        
        # 派生AES密钥
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecc-encryption',
            backend=default_backend()
        ).derive(shared_key)
        
        # 使用AES加密
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # 序列化临时公钥
        ephemeral_pub_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 组合结果
        result = ephemeral_pub_bytes + b'|||' + iv + b'|||' + ciphertext
        
        if output_format == 'base64':
            return base64.b64encode(result).decode('utf-8')
        elif output_format == 'hex':
            return result.hex()
        else:
            return result
    
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
            result = base64.b64decode(ciphertext)
        elif input_format == 'hex':
            result = bytes.fromhex(ciphertext)
        else:
            result = ciphertext
        
        # 分离组件
        parts = result.split(b'|||')
        ephemeral_pub_bytes = parts[0]
        iv = parts[1]
        ciphertext = parts[2]
        
        # 加载临时公钥
        ephemeral_public = serialization.load_pem_public_key(
            ephemeral_pub_bytes,
            backend=default_backend()
        )
        
        # ECDH密钥协商
        shared_key = self.private_key.exchange(ec.ECDH(), ephemeral_public)
        
        # 派生AES密钥
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecc-encryption',
            backend=default_backend()
        ).derive(shared_key)
        
        # 使用AES解密
        cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
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
        
        signature = self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
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
        
        signature = base64.b64decode(signature)
        
        try:
            self.public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False
    
    def export_public_key(self):
        """导出公钥"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def export_private_key(self):
        """导出私钥"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    
    @staticmethod
    def generate_key_pair(curve='SECP256R1'):
        """生成密钥对"""
        curve_obj = ECCCipher.CURVES.get(curve, ec.SECP256R1())
        private_key = ec.generate_private_key(curve_obj, default_backend())
        return private_key, private_key.public_key()
