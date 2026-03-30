"""
配置管理器模块
"""
import json
import os
from pathlib import Path


class ConfigManager:
    """配置管理器类"""
    
    DEFAULT_CONFIG = {
        'last_algorithm': 'AES',
        'last_mode': 'CBC',
        'output_format': 'base64',
        'theme': 'light',
        'api_endpoints': {
            'sojson': 'https://www.sojson.com/encrypt.html',
            'tooltt': 'https://tooltt.com/encrypt/',
            'jsons': 'https://www.jsons.cn/encrypt/'
        },
        'history_limit': 100,
        'auto_save': True
    }
    
    def __init__(self, config_dir=None):
        """
        初始化配置管理器
        
        Args:
            config_dir: 配置目录路径
        """
        if config_dir is None:
            config_dir = os.path.join(str(Path.home()), '.cryptotool')
        
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / 'config.json'
        self.history_file = self.config_dir / 'history.json'
        
        # 确保配置目录存在
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # 加载配置
        self.config = self.load_config()
    
    def load_config(self):
        """加载配置"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                # 合并默认配置
                return {**self.DEFAULT_CONFIG, **config}
            except Exception:
                return self.DEFAULT_CONFIG.copy()
        return self.DEFAULT_CONFIG.copy()
    
    def save_config(self):
        """保存配置"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"保存配置失败: {e}")
            return False
    
    def get(self, key, default=None):
        """获取配置项"""
        return self.config.get(key, default)
    
    def set(self, key, value):
        """设置配置项"""
        self.config[key] = value
        if self.config.get('auto_save', True):
            self.save_config()
    
    def get_api_endpoint(self, name):
        """获取API端点"""
        endpoints = self.config.get('api_endpoints', {})
        return endpoints.get(name)
    
    def set_api_endpoint(self, name, url):
        """设置API端点"""
        if 'api_endpoints' not in self.config:
            self.config['api_endpoints'] = {}
        self.config['api_endpoints'][name] = url
        if self.config.get('auto_save', True):
            self.save_config()
    
    def load_history(self):
        """加载历史记录"""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return []
        return []
    
    def save_history(self, history):
        """保存历史记录"""
        try:
            limit = self.config.get('history_limit', 100)
            if len(history) > limit:
                history = history[-limit:]
            
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"保存历史记录失败: {e}")
            return False
    
    def add_history(self, record):
        """添加历史记录"""
        history = self.load_history()
        history.append(record)
        return self.save_history(history)
    
    def clear_history(self):
        """清空历史记录"""
        return self.save_history([])
