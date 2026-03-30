"""
CryptoTool 主窗口
"""
import sys
import os
from datetime import datetime

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QComboBox, QPushButton, QGroupBox,
    QTabWidget, QSplitter, QStatusBar, QMenuBar, QMenu, QMessageBox,
    QFileDialog, QCheckBox, QSpinBox, QGridLayout, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QAction

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.symmetric import AESCipher, DESCipher, RC4Cipher, TripleDESCipher
from src.asymmetric import RSACipher, ECCCipher
from src.digest import HashAlgorithms, HMACAlgorithms, HashCracker
from src.encoding import BaseEncodings, URLEncoding, HTMLEncoding
from src.chinese import SM2Cipher, SM3Hash, SM4Cipher
from utils import ConfigManager, CryptoUtils
from api import FreeAPIClient, CustomAPIClient


class CryptoWorker(QThread):
    """加密解密工作线程"""
    result = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            self.result.emit(str(result))
        except Exception as e:
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    """主窗口类"""
    
    def __init__(self):
        super().__init__()
        self.config = ConfigManager()
        self.crypto_utils = CryptoUtils()
        self.worker = None
        self.history = []
        
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle('CryptoTool - Burp Suite 加解密工具')
        self.setMinimumSize(900, 700)
        
        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 创建标签页
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # 创建各个标签页
        self.create_crypto_tab()
        self.create_hash_tab()
        self.create_encoding_tab()
        self.create_batch_tab()
        self.create_api_tab()
        self.create_history_tab()
        
        # 状态栏
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage('就绪')
        
        # 菜单栏
        self.create_menu_bar()
    
    def create_menu_bar(self):
        """创建菜单栏"""
        menubar = self.menuBar()
        
        # 文件菜单
        file_menu = menubar.addMenu('文件')
        
        import_action = QAction('导入', self)
        import_action.triggered.connect(self.import_data)
        file_menu.addAction(import_action)
        
        export_action = QAction('导出', self)
        export_action.triggered.connect(self.export_data)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('退出', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # 工具菜单
        tools_menu = menubar.addMenu('工具')
        
        generate_key_action = QAction('生成密钥', self)
        generate_key_action.triggered.connect(self.generate_key)
        tools_menu.addAction(generate_key_action)
        
        # 帮助菜单
        help_menu = menubar.addMenu('帮助')
        
        about_action = QAction('关于', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_crypto_tab(self):
        """创建加解密标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 算法选择区域
        algo_group = QGroupBox('算法设置')
        algo_layout = QGridLayout()
        
        # 算法类型
        algo_layout.addWidget(QLabel('算法类型:'), 0, 0)
        self.algo_type_combo = QComboBox()
        self.algo_type_combo.addItems(['AES', 'DES', '3DES', 'RC4', 'RSA', 'ECC', 'SM2', 'SM4'])
        self.algo_type_combo.currentTextChanged.connect(self.on_algo_type_changed)
        algo_layout.addWidget(self.algo_type_combo, 0, 1)
        
        # 加密模式
        algo_layout.addWidget(QLabel('加密模式:'), 0, 2)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(['CBC', 'ECB', 'CTR', 'GCM', 'CFB', 'OFB'])
        algo_layout.addWidget(self.mode_combo, 0, 3)
        
        # 操作类型
        algo_layout.addWidget(QLabel('操作:'), 0, 4)
        self.operation_combo = QComboBox()
        self.operation_combo.addItems(['加密', '解密', '签名', '验签'])
        algo_layout.addWidget(self.operation_combo, 0, 5)
        
        # 输出格式
        algo_layout.addWidget(QLabel('输出格式:'), 1, 0)
        self.output_format_combo = QComboBox()
        self.output_format_combo.addItems(['Base64', 'Hex'])
        algo_layout.addWidget(self.output_format_combo, 1, 1)
        
        # 密钥输入
        algo_layout.addWidget(QLabel('密钥:'), 1, 2)
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText('输入密钥（留空自动生成）')
        algo_layout.addWidget(self.key_input, 1, 3, 1, 2)
        
        # 生成密钥按钮
        self.gen_key_btn = QPushButton('生成密钥')
        self.gen_key_btn.clicked.connect(self.generate_key)
        algo_layout.addWidget(self.gen_key_btn, 1, 5)
        
        # IV输入
        algo_layout.addWidget(QLabel('IV/Nonce:'), 2, 0)
        self.iv_input = QLineEdit()
        self.iv_input.setPlaceholderText('输入IV（可选）')
        algo_layout.addWidget(self.iv_input, 2, 1, 1, 2)
        
        # 生成IV按钮
        self.gen_iv_btn = QPushButton('生成IV')
        self.gen_iv_btn.clicked.connect(self.generate_iv)
        algo_layout.addWidget(self.gen_iv_btn, 2, 3)
        
        algo_group.setLayout(algo_layout)
        layout.addWidget(algo_group)
        
        # 输入输出区域
        io_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # 输入区域
        input_group = QGroupBox('输入')
        input_layout = QVBoxLayout()
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText('输入要加密/解密的数据...')
        input_layout.addWidget(self.input_text)
        input_group.setLayout(input_layout)
        io_splitter.addWidget(input_group)
        
        # 输出区域
        output_group = QGroupBox('输出')
        output_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText('结果将显示在这里...')
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        io_splitter.addWidget(output_group)
        
        layout.addWidget(io_splitter)
        
        # 操作按钮
        btn_layout = QHBoxLayout()
        
        self.execute_btn = QPushButton('执行')
        self.execute_btn.clicked.connect(self.execute_crypto)
        self.execute_btn.setStyleSheet('QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 10px; }')
        btn_layout.addWidget(self.execute_btn)
        
        self.clear_btn = QPushButton('清空')
        self.clear_btn.clicked.connect(self.clear_fields)
        btn_layout.addWidget(self.clear_btn)
        
        self.copy_btn = QPushButton('复制结果')
        self.copy_btn.clicked.connect(self.copy_result)
        btn_layout.addWidget(self.copy_btn)
        
        self.swap_btn = QPushButton('交换输入输出')
        self.swap_btn.clicked.connect(self.swap_io)
        btn_layout.addWidget(self.swap_btn)
        
        layout.addLayout(btn_layout)
        
        self.tab_widget.addTab(tab, '加解密')
    
    def create_hash_tab(self):
        """创建哈希标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 创建子标签页
        hash_tabs = QTabWidget()
        
        # === 哈希计算 ===
        calc_tab = QWidget()
        calc_layout = QVBoxLayout(calc_tab)
        
        # 算法选择
        algo_layout = QHBoxLayout()
        algo_layout.addWidget(QLabel('哈希算法:'))
        self.hash_algo_combo = QComboBox()
        self.hash_algo_combo.addItems(['MD5', 'SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'SHA3-256', 'RIPEMD160', 'SM3'])
        algo_layout.addWidget(self.hash_algo_combo)
        
        algo_layout.addWidget(QLabel('输出格式:'))
        self.hash_format_combo = QComboBox()
        self.hash_format_combo.addItems(['Hex', 'Base64'])
        algo_layout.addWidget(self.hash_format_combo)
        
        algo_layout.addStretch()
        calc_layout.addLayout(algo_layout)
        
        # 输入
        calc_layout.addWidget(QLabel('输入:'))
        self.hash_input = QTextEdit()
        self.hash_input.setPlaceholderText('输入要计算哈希的数据...')
        calc_layout.addWidget(self.hash_input)
        
        # 计算按钮
        calc_btn = QPushButton('计算哈希')
        calc_btn.clicked.connect(self.calculate_hash)
        calc_layout.addWidget(calc_btn)
        
        # 输出
        calc_layout.addWidget(QLabel('哈希值:'))
        self.hash_output = QTextEdit()
        self.hash_output.setReadOnly(True)
        calc_layout.addWidget(self.hash_output)
        
        hash_tabs.addTab(calc_tab, '哈希计算')
        
        # === 哈希破解 ===
        crack_tab = QWidget()
        crack_layout = QVBoxLayout(crack_tab)
        
        info_label = QLabel('注意：哈希是单向函数，破解通过查询数据库或字典攻击实现')
        info_label.setStyleSheet('color: #FF9800; padding: 5px;')
        crack_layout.addWidget(info_label)
        
        # 输入哈希
        crack_layout.addWidget(QLabel('输入哈希值:'))
        self.crack_hash_input = QLineEdit()
        self.crack_hash_input.setPlaceholderText('输入要破解的哈希值（如MD5/SHA1/SHA256）...')
        crack_layout.addWidget(self.crack_hash_input)
        
        # 自动识别哈希类型
        self.crack_type_label = QLabel('识别类型: 等待输入...')
        self.crack_type_label.setStyleSheet('color: #666;')
        crack_layout.addWidget(self.crack_type_label)
        
        # 破解方法选择
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel('破解方法:'))
        self.crack_method_combo = QComboBox()
        self.crack_method_combo.addItems(['综合破解', '在线查询', '字典攻击', '暴力破解(4位数字)'])
        method_layout.addWidget(self.crack_method_combo)
        crack_layout.addLayout(method_layout)
        
        # 破解按钮
        crack_btn = QPushButton('开始破解')
        crack_btn.clicked.connect(self.crack_hash)
        crack_btn.setStyleSheet('QPushButton { background-color: #FF5722; color: white; font-weight: bold; padding: 10px; }')
        crack_layout.addWidget(crack_btn)
        
        # 结果
        crack_layout.addWidget(QLabel('破解结果:'))
        self.crack_output = QTextEdit()
        self.crack_output.setReadOnly(True)
        crack_layout.addWidget(self.crack_output)
        
        # 自动识别哈希类型
        self.crack_hash_input.textChanged.connect(self.auto_identify_hash)
        
        hash_tabs.addTab(crack_tab, '哈希破解')
        
        layout.addWidget(hash_tabs)
        
        self.tab_widget.addTab(tab, '哈希')
    
    def create_encoding_tab(self):
        """创建编码标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 编码类型选择
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel('编码类型:'))
        self.encoding_type_combo = QComboBox()
        self.encoding_type_combo.addItems(['Base64', 'Base32', 'Base58', 'URL编码', 'HTML编码'])
        type_layout.addWidget(self.encoding_type_combo)
        
        type_layout.addWidget(QLabel('操作:'))
        self.encoding_op_combo = QComboBox()
        self.encoding_op_combo.addItems(['编码', '解码'])
        type_layout.addWidget(self.encoding_op_combo)
        
        type_layout.addStretch()
        layout.addLayout(type_layout)
        
        # 输入
        layout.addWidget(QLabel('输入:'))
        self.encoding_input = QTextEdit()
        self.encoding_input.setPlaceholderText('输入要编码/解码的数据...')
        layout.addWidget(self.encoding_input)
        
        # 执行按钮
        exec_btn = QPushButton('执行')
        exec_btn.clicked.connect(self.execute_encoding)
        layout.addWidget(exec_btn)
        
        # 输出
        layout.addWidget(QLabel('结果:'))
        self.encoding_output = QTextEdit()
        self.encoding_output.setReadOnly(True)
        layout.addWidget(self.encoding_output)
        
        self.tab_widget.addTab(tab, '编码')
    
    def create_batch_tab(self):
        """创建批量处理标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 设置区域
        settings_layout = QHBoxLayout()
        settings_layout.addWidget(QLabel('算法:'))
        self.batch_algo_combo = QComboBox()
        self.batch_algo_combo.addItems(['AES', 'DES', 'MD5', 'SHA256', 'Base64'])
        settings_layout.addWidget(self.batch_algo_combo)
        
        settings_layout.addWidget(QLabel('操作:'))
        self.batch_op_combo = QComboBox()
        self.batch_op_combo.addItems(['加密', '解密'])
        settings_layout.addWidget(self.batch_op_combo)
        
        settings_layout.addWidget(QLabel('密钥:'))
        self.batch_key_input = QLineEdit()
        self.batch_key_input.setPlaceholderText('输入密钥')
        settings_layout.addWidget(self.batch_key_input)
        
        layout.addLayout(settings_layout)
        
        # 输入
        layout.addWidget(QLabel('输入（每行一条）:'))
        self.batch_input = QTextEdit()
        self.batch_input.setPlaceholderText('输入多行数据，每行一条...')
        layout.addWidget(self.batch_input)
        
        # 执行按钮
        batch_btn = QPushButton('批量处理')
        batch_btn.clicked.connect(self.execute_batch)
        layout.addWidget(batch_btn)
        
        # 输出
        layout.addWidget(QLabel('结果:'))
        self.batch_output = QTextEdit()
        self.batch_output.setReadOnly(True)
        layout.addWidget(self.batch_output)
        
        self.tab_widget.addTab(tab, '批量处理')
    
    def create_api_tab(self):
        """创建在线API标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 说明
        info_label = QLabel('使用免费在线API进行加解密操作')
        info_label.setStyleSheet('color: #666; padding: 5px;')
        layout.addWidget(info_label)
        
        # API选择
        api_group = QGroupBox('选择API')
        api_layout = QGridLayout()
        
        api_layout.addWidget(QLabel('API服务:'), 0, 0)
        self.api_service_combo = QComboBox()
        self.api_service_combo.addItems([
            'Base64编码', 'Base64解码', 
            'MD5加密', 'SHA1加密', 'SHA256加密', 'SHA512加密',
            'URL编码', 'URL解码'
        ])
        api_layout.addWidget(self.api_service_combo, 0, 1)
        
        # 测试按钮
        self.test_api_btn = QPushButton('测试API')
        self.test_api_btn.clicked.connect(self.test_api_connection)
        api_layout.addWidget(self.test_api_btn, 0, 2)
        
        api_group.setLayout(api_layout)
        layout.addWidget(api_group)
        
        # 输入输出区域
        io_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # 输入
        input_group = QGroupBox('输入')
        input_layout = QVBoxLayout()
        self.api_input = QTextEdit()
        self.api_input.setPlaceholderText('输入要处理的数据...')
        input_layout.addWidget(self.api_input)
        input_group.setLayout(input_layout)
        io_splitter.addWidget(input_group)
        
        # 输出
        output_group = QGroupBox('输出')
        output_layout = QVBoxLayout()
        self.api_output = QTextEdit()
        self.api_output.setReadOnly(True)
        self.api_output.setPlaceholderText('结果将显示在这里...')
        output_layout.addWidget(self.api_output)
        output_group.setLayout(output_layout)
        io_splitter.addWidget(output_group)
        
        layout.addWidget(io_splitter)
        
        # 操作按钮
        btn_layout = QHBoxLayout()
        
        self.api_execute_btn = QPushButton('调用API')
        self.api_execute_btn.clicked.connect(self.execute_api_call)
        self.api_execute_btn.setStyleSheet('QPushButton { background-color: #2196F3; color: white; font-weight: bold; padding: 10px; }')
        btn_layout.addWidget(self.api_execute_btn)
        
        self.api_clear_btn = QPushButton('清空')
        self.api_clear_btn.clicked.connect(lambda: (self.api_input.clear(), self.api_output.clear()))
        btn_layout.addWidget(self.api_clear_btn)
        
        self.api_copy_btn = QPushButton('复制结果')
        self.api_copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.api_output.toPlainText()) if self.api_output.toPlainText() else None)
        btn_layout.addWidget(self.api_copy_btn)
        
        layout.addLayout(btn_layout)
        
        # 状态标签
        self.api_status_label = QLabel('就绪')
        self.api_status_label.setStyleSheet('color: #999;')
        layout.addWidget(self.api_status_label)
        
        self.tab_widget.addTab(tab, '在线API')
    
    def create_history_tab(self):
        """创建历史记录标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # 操作按钮
        btn_layout = QHBoxLayout()
        
        refresh_btn = QPushButton('刷新')
        refresh_btn.clicked.connect(self.refresh_history)
        btn_layout.addWidget(refresh_btn)
        
        clear_btn = QPushButton('清空历史')
        clear_btn.clicked.connect(self.clear_history)
        btn_layout.addWidget(clear_btn)
        
        export_btn = QPushButton('导出历史')
        export_btn.clicked.connect(self.export_history)
        btn_layout.addWidget(export_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        # 历史列表
        self.history_text = QTextEdit()
        self.history_text.setReadOnly(True)
        layout.addWidget(self.history_text)
        
        self.tab_widget.addTab(tab, '历史记录')
    
    def on_algo_type_changed(self, algo_type):
        """算法类型改变时的处理"""
        # 更新模式选项
        self.mode_combo.clear()
        
        if algo_type in ['AES', 'SM4']:
            self.mode_combo.addItems(['CBC', 'ECB', 'CTR', 'GCM', 'CFB', 'OFB'])
        elif algo_type in ['DES', '3DES']:
            self.mode_combo.addItems(['CBC', 'ECB'])
        elif algo_type in ['RC4', 'RSA', 'ECC', 'SM2']:
            self.mode_combo.setEnabled(False)
            return
        
        self.mode_combo.setEnabled(True)
    
    def execute_crypto(self):
        """执行加解密操作"""
        algo_type = self.algo_type_combo.currentText()
        mode = self.mode_combo.currentText()
        operation = self.operation_combo.currentText()
        output_format = self.output_format_combo.currentText().lower()
        
        input_data = self.input_text.toPlainText()
        key = self.key_input.text()
        iv = self.iv_input.text()
        
        if not input_data:
            QMessageBox.warning(self, '警告', '请输入数据')
            return
        
        try:
            result = self._perform_crypto(algo_type, mode, operation, output_format, input_data, key, iv)
            self.output_text.setText(result)
            
            # 添加到历史
            self.add_to_history({
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'type': algo_type,
                'operation': operation,
                'input': input_data[:50] + '...' if len(input_data) > 50 else input_data,
                'output': result[:50] + '...' if len(result) > 50 else result
            })
            
            self.status_bar.showMessage('执行成功')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'执行失败: {str(e)}')
            self.status_bar.showMessage('执行失败')
    
    def _perform_crypto(self, algo_type, mode, operation, output_format, input_data, key, iv):
        """执行具体的加解密操作"""
        key_bytes = key.encode('utf-8') if key else None
        iv_bytes = bytes.fromhex(iv) if iv else None
        
        if algo_type == 'AES':
            cipher = AESCipher(key=key_bytes, mode=mode, iv=iv_bytes)
            if operation == '加密':
                return cipher.encrypt(input_data, output_format)
            else:
                return cipher.decrypt(input_data, output_format)
        
        elif algo_type == 'DES':
            cipher = DESCipher(key=key_bytes, mode=mode, iv=iv_bytes)
            if operation == '加密':
                return cipher.encrypt(input_data, output_format)
            else:
                return cipher.decrypt(input_data, output_format)
        
        elif algo_type == '3DES':
            cipher = TripleDESCipher(key=key_bytes, mode=mode, iv=iv_bytes)
            if operation == '加密':
                return cipher.encrypt(input_data, output_format)
            else:
                return cipher.decrypt(input_data, output_format)
        
        elif algo_type == 'RC4':
            cipher = RC4Cipher(key=key_bytes)
            if operation == '加密':
                return cipher.encrypt(input_data, output_format)
            else:
                return cipher.decrypt(input_data, output_format)
        
        elif algo_type == 'RSA':
            cipher = RSACipher(key=key)
            if operation == '加密':
                return cipher.encrypt(input_data, output_format)
            elif operation == '解密':
                return cipher.decrypt(input_data, output_format)
            elif operation == '签名':
                return cipher.sign(input_data)
            elif operation == '验签':
                return str(cipher.verify(input_data, key))
        
        elif algo_type == 'ECC':
            cipher = ECCCipher()
            if operation == '加密':
                return cipher.encrypt(input_data, output_format)
            elif operation == '解密':
                return cipher.decrypt(input_data, output_format)
            elif operation == '签名':
                return cipher.sign(input_data)
            elif operation == '验签':
                return str(cipher.verify(input_data, key))
        
        elif algo_type == 'SM2':
            try:
                cipher = SM2Cipher()
                if operation == '加密':
                    return cipher.encrypt(input_data, output_format)
                elif operation == '解密':
                    return cipher.decrypt(input_data, output_format)
                elif operation == '签名':
                    return cipher.sign(input_data)
                elif operation == '验签':
                    return str(cipher.verify(input_data, key))
            except ImportError:
                return 'SM2需要安装gmssl库: pip install gmssl'
        
        elif algo_type == 'SM4':
            try:
                cipher = SM4Cipher(key=key_bytes, mode=mode, iv=iv_bytes)
                if operation == '加密':
                    return cipher.encrypt(input_data, output_format)
                else:
                    return cipher.decrypt(input_data, output_format)
            except ImportError:
                return 'SM4需要安装gmssl库: pip install gmssl'
        
        return '不支持的算法'
    
    def calculate_hash(self):
        """计算哈希值"""
        algo = self.hash_algo_combo.currentText()
        output_format = self.hash_format_combo.currentText().lower()
        input_data = self.hash_input.toPlainText()
        
        if not input_data:
            QMessageBox.warning(self, '警告', '请输入数据')
            return
        
        try:
            if algo == 'SM3':
                try:
                    sm3 = SM3Hash()
                    result = sm3.hash(input_data, output_format)
                except ImportError:
                    result = 'SM3需要安装gmssl库: pip install gmssl'
            else:
                hash_algo = HashAlgorithms(algo.replace('-', '_'))
                result = hash_algo.hash(input_data, output_format)
            
            self.hash_output.setText(result)
            self.status_bar.showMessage('哈希计算完成')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'哈希计算失败: {str(e)}')
    
    def auto_identify_hash(self, hash_str):
        """自动识别哈希类型"""
        if not hash_str:
            self.crack_type_label.setText('识别类型: 等待输入...')
            return
        
        # 移除空格和换行
        hash_str = hash_str.strip()
        
        # 识别哈希类型
        hash_len = len(hash_str)
        hash_types = {
            32: 'MD5 / MD4 / NTLM',
            40: 'SHA1 / RIPEMD160',
            56: 'SHA224',
            64: 'SHA256',
            96: 'SHA384',
            128: 'SHA512'
        }
        
        identified = hash_types.get(hash_len, '未知类型')
        self.crack_type_label.setText(f'识别类型: {identified} (长度: {hash_len})')
    
    def crack_hash(self):
        """破解哈希"""
        hash_str = self.crack_hash_input.text().strip()
        method = self.crack_method_combo.currentText()
        
        if not hash_str:
            QMessageBox.warning(self, '警告', '请输入哈希值')
            return
        
        self.crack_output.setText('正在破解，请稍候...')
        QApplication.processEvents()
        
        try:
            cracker = HashCracker()
            
            # 根据选择的方法破解
            if method == '综合破解':
                methods = ['online', 'dictionary', 'brute']
            elif method == '在线查询':
                methods = ['online']
            elif method == '字典攻击':
                methods = ['dictionary']
            elif method == '暴力破解(4位数字)':
                methods = ['brute']
            else:
                methods = ['online', 'dictionary']
            
            result = cracker.crack(hash_str, methods=methods)
            
            if result['plaintext']:
                self.crack_output.setText(
                    f"破解成功！\n\n"
                    f"哈希值: {result['hash']}\n"
                    f"类型: {result['type']}\n"
                    f"明文: {result['plaintext']}\n"
                    f"方法: {result['method']}"
                )
                self.status_bar.showMessage('哈希破解成功')
            else:
                self.crack_output.setText(
                    f"破解失败\n\n"
                    f"哈希值: {result['hash']}\n"
                    f"类型: {result['type']}\n\n"
                    f"可能原因:\n"
                    f"1. 哈希不在在线数据库中\n"
                    f"2. 密码不在内置字典中\n"
                    f"3. 密码过于复杂\n\n"
                    f"建议:\n"
                    f"- 尝试使用更大的字典文件\n"
                    f"- 暴力破解仅适用于简单密码"
                )
                self.status_bar.showMessage('哈希破解失败')
        
        except Exception as e:
            self.crack_output.setText(f'破解出错: {str(e)}')
            self.status_bar.showMessage('哈希破解出错')
    
    def execute_encoding(self):
        """执行编码操作"""
        encoding_type = self.encoding_type_combo.currentText()
        operation = self.encoding_op_combo.currentText()
        input_data = self.encoding_input.toPlainText()
        
        if not input_data:
            QMessageBox.warning(self, '警告', '请输入数据')
            return
        
        try:
            is_encode = operation == '编码'
            
            if encoding_type == 'Base64':
                result = BaseEncodings.base64_encode(input_data) if is_encode else BaseEncodings.base64_decode(input_data)
            elif encoding_type == 'Base32':
                result = BaseEncodings.base32_encode(input_data) if is_encode else BaseEncodings.base32_decode(input_data)
            elif encoding_type == 'Base58':
                result = BaseEncodings.base58_encode(input_data) if is_encode else BaseEncodings.base58_decode(input_data)
            elif encoding_type == 'URL编码':
                result = URLEncoding.encode(input_data) if is_encode else URLEncoding.decode(input_data)
            elif encoding_type == 'HTML编码':
                result = HTMLEncoding.encode(input_data) if is_encode else HTMLEncoding.decode(input_data)
            else:
                result = '不支持的编码类型'
            
            self.encoding_output.setText(result)
            self.status_bar.showMessage('编码操作完成')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'编码操作失败: {str(e)}')
    
    def execute_batch(self):
        """执行批量处理"""
        algo = self.batch_algo_combo.currentText()
        operation = self.batch_op_combo.currentText()
        key = self.batch_key_input.text()
        input_data = self.batch_input.toPlainText()
        
        if not input_data:
            QMessageBox.warning(self, '警告', '请输入数据')
            return
        
        lines = input_data.strip().split('\n')
        results = []
        
        for line in lines:
            if not line.strip():
                continue
            
            try:
                if algo == 'AES':
                    cipher = AESCipher(key=key.encode('utf-8') if key else None)
                    result = cipher.encrypt(line) if operation == '加密' else cipher.decrypt(line)
                elif algo == 'DES':
                    cipher = DESCipher(key=key.encode('utf-8') if key else None)
                    result = cipher.encrypt(line) if operation == '加密' else cipher.decrypt(line)
                elif algo == 'MD5':
                    hash_algo = HashAlgorithms('MD5')
                    result = hash_algo.hash(line)
                elif algo == 'SHA256':
                    hash_algo = HashAlgorithms('SHA256')
                    result = hash_algo.hash(line)
                elif algo == 'Base64':
                    result = BaseEncodings.base64_encode(line) if operation == '加密' else BaseEncodings.base64_decode(line)
                else:
                    result = '不支持的算法'
                
                results.append(result)
            except Exception as e:
                results.append(f'错误: {str(e)}')
        
        self.batch_output.setText('\n'.join(results))
        self.status_bar.showMessage(f'批量处理完成，共处理 {len(results)} 条数据')
    
    def execute_api_call(self):
        """执行在线API调用"""
        api_service = self.api_service_combo.currentText()
        input_data = self.api_input.toPlainText()
        
        if not input_data:
            QMessageBox.warning(self, '警告', '请输入数据')
            return
        
        self.api_status_label.setText('调用中...')
        self.api_status_label.setStyleSheet('color: #FF9800;')
        QApplication.processEvents()
        
        try:
            client = FreeAPIClient()
            
            # 映射API服务名称到方法
            api_map = {
                'Base64编码': 'base64_encode',
                'Base64解码': 'base64_decode',
                'MD5加密': 'md5',
                'SHA1加密': 'sha1',
                'SHA256加密': 'sha256',
                'SHA512加密': 'sha512',
                'URL编码': 'url_encode',
                'URL解码': 'url_decode'
            }
            
            api_name = api_map.get(api_service)
            if not api_name:
                raise ValueError(f'不支持的API服务: {api_service}')
            
            result = client.call_api(api_name, input_data)
            
            self.api_output.setText(str(result))
            self.api_status_label.setText('调用成功')
            self.api_status_label.setStyleSheet('color: #4CAF50;')
            
            # 添加到历史
            self.add_to_history({
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'type': 'API',
                'operation': api_service,
                'input': input_data[:50] + '...' if len(input_data) > 50 else input_data,
                'output': str(result)[:50] + '...' if len(str(result)) > 50 else str(result)
            })
            
        except Exception as e:
            self.api_output.setText(f'调用失败: {str(e)}')
            self.api_status_label.setText('调用失败')
            self.api_status_label.setStyleSheet('color: #F44336;')
    
    def test_api_connection(self):
        """测试API连接"""
        api_service = self.api_service_combo.currentText()
        
        self.api_status_label.setText('测试中...')
        self.api_status_label.setStyleSheet('color: #FF9800;')
        QApplication.processEvents()
        
        try:
            client = FreeAPIClient(timeout=5)
            
            api_map = {
                'Base64编码': 'base64_encode',
                'Base64解码': 'base64_decode',
                'MD5加密': 'md5',
                'SHA1加密': 'sha1',
                'SHA256加密': 'sha256',
                'SHA512加密': 'sha512',
                'URL编码': 'url_encode',
                'URL解码': 'url_decode'
            }
            
            api_name = api_map.get(api_service)
            if not api_name:
                raise ValueError(f'不支持的API服务: {api_service}')
            
            # 发送测试请求
            result = client.call_api(api_name, 'test')
            
            self.api_status_label.setText(f'{api_service} 连接正常')
            self.api_status_label.setStyleSheet('color: #4CAF50;')
            self.api_output.setText(f'测试结果: {result}')
            
        except Exception as e:
            self.api_status_label.setText(f'{api_service} 连接失败')
            self.api_status_label.setStyleSheet('color: #F44336;')
            self.api_output.setText(f'错误: {str(e)}')
    
    def add_api_endpoint(self):
        """添加API端点"""
        name = self.api_name_input.text() if hasattr(self, 'api_name_input') else ''
        url = self.api_url_input.text() if hasattr(self, 'api_url_input') else ''
        
        if not name or not url:
            QMessageBox.warning(self, '警告', '请填写名称和URL')
            return
        
        self.config.set_api_endpoint(name, url)
        if hasattr(self, 'api_name_input'):
            self.api_name_input.clear()
        if hasattr(self, 'api_url_input'):
            self.api_url_input.clear()
    
    def refresh_api_list(self):
        """刷新API列表"""
        pass
    
    def add_to_history(self, record):
        """添加历史记录"""
        self.history.append(record)
        self.config.add_history(record)
    
    def refresh_history(self):
        """刷新历史记录"""
        self.history = self.config.load_history()
        text = '\n'.join([
            f"[{r.get('time', '')}] {r.get('type', '')} - {r.get('operation', '')}: {r.get('input', '')} -> {r.get('output', '')}"
            for r in self.history
        ])
        self.history_text.setText(text)
    
    def clear_history(self):
        """清空历史记录"""
        reply = QMessageBox.question(self, '确认', '确定要清空历史记录吗？')
        if reply == QMessageBox.StandardButton.Yes:
            self.config.clear_history()
            self.history.clear()
            self.history_text.clear()
    
    def export_history(self):
        """导出历史记录"""
        filepath, _ = QFileDialog.getSaveFileName(self, '导出历史', '', 'JSON文件 (*.json)')
        if filepath:
            try:
                import json
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(self.history, f, indent=4, ensure_ascii=False)
                QMessageBox.information(self, '成功', '历史记录已导出')
            except Exception as e:
                QMessageBox.critical(self, '错误', f'导出失败: {str(e)}')
    
    def generate_key(self):
        """生成密钥"""
        algo_type = self.algo_type_combo.currentText()
        
        try:
            if algo_type == 'AES':
                key = AESCipher.generate_key().hex()
            elif algo_type == 'DES':
                key = DESCipher.generate_key().hex()
            elif algo_type == '3DES':
                key = TripleDESCipher.generate_key().hex()
            elif algo_type == 'RSA':
                key = 'RSA密钥对已生成，请查看输出'
                cipher = RSACipher()
                self.output_text.setText(
                    f"公钥:\n{cipher.export_public_key()}\n\n私钥:\n{cipher.export_private_key()}"
                )
                return
            else:
                key = CryptoUtils.generate_random_hex(16)
            
            self.key_input.setText(key)
            self.status_bar.showMessage('密钥已生成')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'密钥生成失败: {str(e)}')
    
    def generate_iv(self):
        """生成IV"""
        self.iv_input.setText(CryptoUtils.generate_random_hex(16))
        self.status_bar.showMessage('IV已生成')
    
    def clear_fields(self):
        """清空字段"""
        self.input_text.clear()
        self.output_text.clear()
        self.key_input.clear()
        self.iv_input.clear()
    
    def copy_result(self):
        """复制结果"""
        result = self.output_text.toPlainText()
        if result:
            QApplication.clipboard().setText(result)
            self.status_bar.showMessage('已复制到剪贴板')
    
    def swap_io(self):
        """交换输入输出"""
        input_text = self.input_text.toPlainText()
        output_text = self.output_text.toPlainText()
        self.input_text.setText(output_text)
        self.output_text.setText(input_text)
    
    def import_data(self):
        """导入数据"""
        filepath, _ = QFileDialog.getOpenFileName(self, '导入文件', '', '所有文件 (*)')
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = f.read()
                self.input_text.setText(data)
                self.status_bar.showMessage(f'已导入: {filepath}')
            except Exception as e:
                QMessageBox.critical(self, '错误', f'导入失败: {str(e)}')
    
    def export_data(self):
        """导出数据"""
        filepath, _ = QFileDialog.getSaveFileName(self, '导出文件', '', '所有文件 (*)')
        if filepath:
            try:
                data = self.output_text.toPlainText()
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(data)
                self.status_bar.showMessage(f'已导出: {filepath}')
            except Exception as e:
                QMessageBox.critical(self, '错误', f'导出失败: {str(e)}')
    
    def load_settings(self):
        """加载设置"""
        last_algo = self.config.get('last_algorithm', 'AES')
        index = self.algo_type_combo.findText(last_algo)
        if index >= 0:
            self.algo_type_combo.setCurrentIndex(index)
        
        last_mode = self.config.get('last_mode', 'CBC')
        index = self.mode_combo.findText(last_mode)
        if index >= 0:
            self.mode_combo.setCurrentIndex(index)
    
    def save_settings(self):
        """保存设置"""
        self.config.set('last_algorithm', self.algo_type_combo.currentText())
        self.config.set('last_mode', self.mode_combo.currentText())
    
    def show_about(self):
        """显示关于对话框"""
        QMessageBox.about(
            self,
            '关于 CryptoTool',
            'CryptoTool v1.0\n\n'
            'Burp Suite 加解密工具\n\n'
            '支持算法:\n'
            '- 对称加密: AES, DES, 3DES, RC4\n'
            '- 非对称加密: RSA, ECC\n'
            '- 国密算法: SM2, SM3, SM4\n'
            '- 哈希算法: MD5, SHA系列, RIPEMD160\n'
            '- 编码算法: Base64, Base32, Base58, URL, HTML\n\n'
            '功能特点:\n'
            '- 简洁的图形界面\n'
            '- 高效的加解密处理\n'
            '- 支持批量操作\n'
            '- 历史记录保存\n'
            '- 可与Burp Suite联动'
        )
    
    def closeEvent(self, event):
        """关闭事件"""
        self.save_settings()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
