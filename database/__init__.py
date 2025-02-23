import sqlite3
import os

class Database:
    def __init__(self, db_path='config.db'):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """初始化数据库和表结构"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 创建API配置表
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_base TEXT NOT NULL,
            api_key TEXT NOT NULL,
            model TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        conn.commit()
        conn.close()

    def save_api_config(self, api_base: str, api_key: str, model: str) -> bool:
        """保存API配置"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 清除旧配置
            cursor.execute("DELETE FROM api_config")
            
            # 插入新配置
            cursor.execute(
                "INSERT INTO api_config (api_base, api_key, model) VALUES (?, ?, ?)",
                (api_base, api_key, model)
            )
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"保存API配置失败: {e}")
            return False

    def get_api_config(self) -> dict:
        """获取API配置"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT api_base, api_key, model FROM api_config LIMIT 1")
            result = cursor.fetchone()
            
            conn.close()
            
            if result:
                return {
                    'api_base': result[0],
                    'api_key': result[1],
                    'model': result[2]
                }
            return {}
        except Exception as e:
            print(f"获取API配置失败: {e}")
            return {}

# 创建全局数据库实例
db = Database()