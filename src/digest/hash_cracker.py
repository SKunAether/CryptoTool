"""
哈希破解模块
"""
import hashlib
import string
import itertools
import os


class HashCracker:
    """哈希破解类"""
    
    # 内置小字典
    COMMON_PASSWORDS = [
        'root', 'admin', 'administrator', 'user', 'guest', 'test', 'sa',
        '123456', '123456789', '12345678', '12345', '1234567', '1234',
        '000000', '111111', '222222', '333333', '666666', '888888',
        'password', 'password1', 'password123', 'qwerty', 'abc123',
        'letmein', 'welcome', 'monkey', 'master', 'dragon', 'login',
        'shadow', 'sunshine', 'princess', 'football', 'baseball',
        'iloveyou', 'trustno1', 'batman', 'superman',
    ]
    
    def __init__(self):
        self.dict_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'config', 'password_dict.txt')
    
    def identify_hash(self, hash_str):
        """识别哈希类型"""
        hash_str = hash_str.strip()
        length = len(hash_str)
        types = {
            32: ['MD5'],
            40: ['SHA1'],
            56: ['SHA224'],
            64: ['SHA256'],
            96: ['SHA384'],
            128: ['SHA512']
        }
        return types.get(length, ['未知'])
    
    def dictionary_attack(self, hash_str, hash_type='md5', wordlist=None):
        """字典攻击"""
        hash_func = self._get_hash_func(hash_type)
        if not hash_func:
            return None
        
        target = hash_str.lower().strip()
        
        # 如果指定了字典文件
        if wordlist is not None:
            if isinstance(wordlist, str):
                return self._attack_with_file(hash_func, target, wordlist)
            else:
                for word in wordlist:
                    if hash_func(word.encode('utf-8')).hexdigest() == target:
                        return word
                return None
        
        # 先用内置小字典快速匹配
        for word in self.COMMON_PASSWORDS:
            if hash_func(word.encode('utf-8')).hexdigest() == target:
                return word
        
        # 再用大字典文件
        if os.path.exists(self.dict_path):
            return self._attack_with_file(hash_func, target, self.dict_path)
        
        return None
    
    def _attack_with_file(self, hash_func, target, filepath):
        """使用字典文件攻击"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word and hash_func(word.encode('utf-8')).hexdigest() == target:
                        return word
        except Exception as e:
            pass
        return None
    
    def brute_force(self, hash_str, hash_type='md5', max_len=4):
        """暴力破解（数字）"""
        hash_func = self._get_hash_func(hash_type)
        if not hash_func:
            return None
        
        target = hash_str.lower().strip()
        charset = string.digits
        
        for length in range(1, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                word = ''.join(combo)
                if hash_func(word.encode('utf-8')).hexdigest() == target:
                    return word
        return None
    
    def crack(self, hash_str, methods=None):
        """综合破解"""
        if methods is None:
            methods = ['dictionary', 'brute']
        
        hash_str = hash_str.strip().lower()
        hash_type = self.identify_hash(hash_str)[0].lower()
        
        result = {'hash': hash_str, 'type': hash_type, 'plaintext': None, 'method': None}
        
        if 'dictionary' in methods:
            plaintext = self.dictionary_attack(hash_str, hash_type)
            if plaintext:
                result['plaintext'] = plaintext
                result['method'] = '字典攻击'
                return result
        
        if 'brute' in methods:
            plaintext = self.brute_force(hash_str, hash_type, max_len=4)
            if plaintext:
                result['plaintext'] = plaintext
                result['method'] = '暴力破解'
                return result
        
        return result
    
    def _get_hash_func(self, hash_type):
        """获取哈希函数"""
        funcs = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512
        }
        return funcs.get(hash_type.lower())
