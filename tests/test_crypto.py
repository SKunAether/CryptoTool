#!/usr/bin/env python3
"""
CryptoTool 测试文件
"""
import sys
import os

# 添加项目目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.symmetric import AESCipher, DESCipher, RC4Cipher, TripleDESCipher
from src.asymmetric import RSACipher, ECCCipher
from src.digest import HashAlgorithms, HMACAlgorithms
from src.encoding import BaseEncodings, URLEncoding, HTMLEncoding


def test_aes():
    """测试AES加密"""
    print("\n=== 测试AES加密 ===")
    cipher = AESCipher()
    plaintext = "Hello World"
    ciphertext = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(ciphertext)
    print(f"原文: {plaintext}")
    print(f"密文: {ciphertext}")
    print(f"解密: {decrypted}")
    assert decrypted == plaintext, "AES解密失败"
    print("[PASS] AES测试通过")


def test_des():
    """测试DES加密"""
    print("\n=== 测试DES加密 ===")
    cipher = DESCipher()
    plaintext = "Test Data"
    ciphertext = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(ciphertext)
    print(f"原文: {plaintext}")
    print(f"密文: {ciphertext}")
    print(f"解密: {decrypted}")
    assert decrypted == plaintext, "DES解密失败"
    print("[PASS] DES测试通过")


def test_rsa():
    """测试RSA加密"""
    print("\n=== 测试RSA加密 ===")
    cipher = RSACipher()
    plaintext = "RSA Test"
    ciphertext = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(ciphertext)
    print(f"原文: {plaintext}")
    print(f"密文: {ciphertext[:50]}...")
    print(f"解密: {decrypted}")
    assert decrypted == plaintext, "RSA解密失败"
    print("[PASS] RSA测试通过")


def test_hash():
    """测试哈希算法"""
    print("\n=== 测试哈希算法 ===")
    data = "Hello World"
    
    for algo in ['MD5', 'SHA256', 'SHA512']:
        hash_algo = HashAlgorithms(algo)
        result = hash_algo.hash(data)
        print(f"{algo}: {result}")
    
    print("[PASS] 哈希测试通过")


def test_encoding():
    """测试编码算法"""
    print("\n=== 测试编码算法 ===")
    data = "Hello World"
    
    # Base64
    encoded = BaseEncodings.base64_encode(data)
    decoded = BaseEncodings.base64_decode(encoded)
    print(f"Base64: {encoded} -> {decoded}")
    assert decoded == data
    
    # URL编码
    url_encoded = URLEncoding.encode("Hello World?test=123")
    url_decoded = URLEncoding.decode(url_encoded)
    print(f"URL: {url_encoded} -> {url_decoded}")
    
    print("[PASS] 编码测试通过")


def main():
    """运行所有测试"""
    print("=" * 50)
    print("  CryptoTool 测试")
    print("=" * 50)
    
    try:
        test_aes()
        test_des()
        test_rsa()
        test_hash()
        test_encoding()
        
        print("\n" + "=" * 50)
        print("  所有测试通过!")
        print("=" * 50)
    except Exception as e:
        print(f"\n测试失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
