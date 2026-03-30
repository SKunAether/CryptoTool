"""
HTML编码模块
"""
import html


class HTMLEncoding:
    """HTML编码类"""
    
    @staticmethod
    def encode(data):
        """
        HTML编码
        
        Args:
            data: 输入数据
            
        Returns:
            编码后的字符串
        """
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return html.escape(data)
    
    @staticmethod
    def decode(data):
        """
        HTML解码
        
        Args:
            data: 编码后的字符串
            
        Returns:
            解码后的字符串
        """
        return html.unescape(data)
    
    @staticmethod
    def encode_entities(data):
        """
        HTML实体编码（所有字符）
        
        Args:
            data: 输入数据
            
        Returns:
            编码后的字符串
        """
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        return ''.join(f'&#{ord(c)};' for c in data)
    
    @staticmethod
    def decode_entities(data):
        """
        HTML实体解码
        
        Args:
            data: 编码后的字符串
            
        Returns:
            解码后的字符串
        """
        import re
        
        def replace_entity(match):
            entity = match.group(1)
            if entity.startswith('#x'):
                return chr(int(entity[2:], 16))
            elif entity.startswith('#'):
                return chr(int(entity[1:]))
            else:
                return html.unescape(f'&{entity};')
        
        pattern = r'&#?x?[a-fA-F0-9]+;'
        return re.sub(pattern, replace_entity, data)
