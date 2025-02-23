from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv
import os
import uuid
import logging
import re
import asyncio
from scanner.rules.engine import RuleEngine, Rule, ScanResult
from scanner.ai.analyzer import AIAnalyzer
from typing import Dict, List

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# 加载环境变量
load_dotenv()

app = Flask(__name__)
CORS(app)

# 配置文件上传目录
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 配置结果保存目录
RESULTS_FOLDER = 'results'
if not os.path.exists(RESULTS_FOLDER):
    os.makedirs(RESULTS_FOLDER)

# 初始化规则引擎和任务存储
rule_engine = RuleEngine()
tasks: Dict[str, dict] = {}

import zipfile
import tempfile
import shutil

def process_contract_file(file_path: str) -> List[ScanResult]:
    """处理单个合约文件"""
    results = []
    try:
        if file_path.endswith(('.sol', '.go', '.rs')):
            results.extend(rule_engine.scan_file(file_path))
    except Exception as e:
        logging.error(f"处理合约文件 {file_path} 时出错: {str(e)}")
    return results

def process_zip_file(zip_path: str) -> List[ScanResult]:
    """处理zip文件，解压并扫描其中的合约文件"""
    results = []
    temp_dir = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
            
        for root, _, files in os.walk(temp_dir):
            for file in files:
                if file.endswith(('.sol', '.go', '.rs')):
                    file_path = os.path.join(root, file)
                    results.extend(process_contract_file(file_path))
    except Exception as e:
        logging.error(f"处理ZIP文件 {zip_path} 时出错: {str(e)}")
    finally:
        shutil.rmtree(temp_dir)
    return results

@app.route('/api/scan', methods=['POST'])
def scan_contract():
    """处理智能合约扫描请求"""
    try:
        # 清空历史任务
        tasks.clear()
        
        # 获取上传的合约文件
        if 'file' not in request.files:
            return jsonify({'error': '没有上传文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '未选择文件'}), 400

        # 生成任务ID和临时文件路径
        task_id = str(uuid.uuid4())
        filename = os.path.join(UPLOAD_FOLDER, f"{task_id}_{file.filename}")
        file.save(filename)

        # 根据文件类型进行处理
        scan_results = []
        if filename.endswith('.zip'):
            scan_results = process_zip_file(filename)
        else:
            scan_results = process_contract_file(filename)

        # 初始化AI分析器
        api_key = request.form.get('apiKey')
        api_base = request.form.get('apiBase')
        model = request.form.get('model', 'gpt-4')
        analyzer = AIAnalyzer(api_key, api_base, model)
        
        # 保存任务信息
        tasks[task_id] = {
            'file_path': filename,
            'scan_results': scan_results,
            'analyzer': analyzer,
            'status': 'processing'
        }
        
        return jsonify({
            'status': 'success',
            'message': '扫描任务已提交',
            'task_id': task_id
        })

    except Exception as e:
        logging.error(f"扫描请求处理出错: {str(e)}")
        return jsonify({'error': str(e)}), 500

from database import db

@app.route('/api/config', methods=['GET', 'POST'])
async def manage_config():
    """管理API配置"""
    if request.method == 'GET':
        try:
            config = db.get_api_config()
            return jsonify(config)
        except Exception as e:
            app.logger.error(f"获取API配置失败: {str(e)}")
            return jsonify({'status': 'error', 'message': '获取API配置失败'}), 500
    else:
        try:
            data = request.json
            if not data:
                return jsonify({'status': 'error', 'message': '请求数据为空'}), 400
                
            api_base = data.get('api_base')
            api_key = data.get('api_key')
            model = data.get('model', 'gpt-4')
            
            if not api_base or not api_key:
                return jsonify({'status': 'error', 'message': '缺少必要的API配置信息'}), 400
                
            if db.save_api_config(api_base, api_key, model):
                return jsonify({'status': 'success', 'message': 'API配置已保存'})
            else:
                return jsonify({'status': 'error', 'message': '保存API配置失败'}), 500
                
        except Exception as e:
            app.logger.error(f"保存API配置失败: {str(e)}")
            return jsonify({'status': 'error', 'message': '保存API配置失败'}), 500

@app.route('/api/rules', methods=['GET', 'POST'])
async def manage_rules():
    """管理扫描规则"""
    if request.method == 'GET':
        try:
            rules = rule_engine.get_rules()
            return jsonify([{
                'id': rule.id,
                'name': rule.name,
                'description': rule.description,
                'severity': rule.severity,
                'category': rule.category
            } for rule in rules])
        except Exception as e:
            app.logger.error(f"获取规则列表失败: {str(e)}")
            return jsonify({'status': 'error', 'message': '获取规则列表失败'}), 500
    else:
        try:
            data = request.json
            app.logger.info(f"收到添加规则请求: {data}")
            
            if not data:
                app.logger.error("请求数据为空")
                return jsonify({'status': 'error', 'message': '请求数据为空'}), 400

            # 验证必要字段
            if 'description' not in data:
                app.logger.error("缺少规则描述字段")
                return jsonify({'status': 'error', 'message': '缺少规则描述字段'}), 400

            # 从数据库获取API配置
            config = db.get_api_config()
            if not config:
                return jsonify({'status': 'error', 'message': 'API配置未设置，请先配置API信息'}), 400
                
            # 初始化AI分析器
            try:
                ai_analyzer = AIAnalyzer(
                    api_key=config['api_key'],
                    api_base=config['api_base'],
                    model=config['model']
                )
            except ValueError as e:
                error_msg = f"AI分析器初始化失败: {str(e)}"
                app.logger.error(error_msg)
                return jsonify({'status': 'error', 'message': error_msg}), 500
            
            # 使用AI服务将自然语言描述转换为规则
            target_langs = data.get('target_langs', [])
            app.logger.info(f"目标语言: {target_langs}")
            
            try:
                app.logger.info("开始创建规则...")
                new_rule = await rule_engine.add_rule_from_description(
                    rule_description=data['description'],
                    target_langs=target_langs,
                    api_key=config['api_key'],
                    api_base=config['api_base'],
                    model=config['model']
                )
                
                if new_rule:
                    success_msg = f"成功创建新规则: {new_rule.id}"
                    app.logger.info(success_msg)
                    return jsonify({
                        'status': 'success',
                        'rule_id': new_rule.id,
                        'message': success_msg
                    })
                else:
                    error_msg = "规则创建失败: 返回值为空"
                    app.logger.error(error_msg)
                    return jsonify({'status': 'error', 'message': error_msg}), 500
                    
            except Exception as e:
                error_msg = f"规则创建过程出错: {str(e)}"
                app.logger.error(error_msg)
                return jsonify({'status': 'error', 'message': error_msg}), 500
                
        except KeyError as e:
            error_msg = f"请求数据缺少必要字段: {str(e)}"
            app.logger.error(error_msg)
            return jsonify({'status': 'error', 'message': error_msg}), 400
        except Exception as e:
            error_msg = f"处理规则请求时出错: {str(e)}"
            app.logger.error(error_msg)
            return jsonify({'status': 'error', 'message': error_msg}), 500

@app.route('/api/results/<task_id>', methods=['GET'])
def get_scan_results(task_id):
    """获取扫描结果"""
    if task_id not in tasks:
        return jsonify({'error': '任务不存在'}), 404
        
    task = tasks[task_id]
    scan_results = task['scan_results']
    
    return jsonify({
        'status': task['status'],
        'results': [{
            'rule_id': result.rule_id,
            'file_path': result.file_path,
            'line_number': result.line_number,
            'matched_code': result.matched_code,
            'severity': result.severity
        } for result in scan_results]
    })

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """获取所有漏洞列表"""
    try:
        # 使用字典来存储唯一的漏洞记录
        unique_vulnerabilities = {}
        
        # 收集所有任务中的漏洞信息
        for task_id, task in tasks.items():
            scan_results = task['scan_results']
            for result in scan_results:
                # 创建唯一标识
                unique_key = f"{result.file_path}_{result.line_number}_{result.rule_id}"
                
                # 只有当漏洞不存在时才添加
                if unique_key not in unique_vulnerabilities:
                    unique_vulnerabilities[unique_key] = {
                        'id': f"{task_id}_{result.rule_id}",
                        'rule_name': result.rule_id,
                        'file_path': result.file_path,
                        'line_number': result.line_number,
                        'severity': result.severity
                    }
        
        return jsonify({
            'status': 'success',
            'vulnerabilities': list(unique_vulnerabilities.values())
        })
    except Exception as e:
        app.logger.error(f"获取漏洞列表失败: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/')
def index():
    """根路由处理"""
    return render_template('index.html')

@app.route('/scan')
def scan():
    """扫描页面"""
    return render_template('scan.html')

@app.route('/analysis')
def analysis():
    """AI分析页面"""
    return render_template('analysis.html')

@app.route('/rules')
def rules():
    """规则管理页面"""
    return render_template('rules.html')

@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    """获取所有任务列表"""
    processing_tasks = []
    completed_tasks = []
    terminated_tasks = []
    
    for task_id, task in tasks.items():
        task_info = {
            'id': task_id,
            'filename': os.path.basename(task['file_path']),
            'status': task['status']
        }
        
        if task['status'] == 'processing':
            processing_tasks.append(task_info)
        elif task['status'] == 'completed':
            task_info['completed_at'] = task.get('completed_at', '')
            completed_tasks.append(task_info)
        elif task['status'] == 'terminated':
            task_info['terminated_at'] = task.get('terminated_at', '')
            task_info['terminate_reason'] = task.get('terminate_reason', '')
            terminated_tasks.append(task_info)
    
    return jsonify({
        'processing': processing_tasks,
        'completed': completed_tasks,
        'terminated': terminated_tasks
    })

@app.route('/api/analyze/<vuln_id>', methods=['GET'])
def analyze_vulnerability(vuln_id):
    """分析指定的漏洞"""
    try:
        app.logger.info(f"开始分析漏洞: {vuln_id}")
        
        # 解析任务ID和规则ID
        try:
            task_id, rule_id = vuln_id.split('_')
        except ValueError:
            app.logger.error(f"无效的漏洞ID格式: {vuln_id}")
            return jsonify({
                'status': 'error',
                'error': '无效的漏洞ID格式'
            }), 400
        
        # 获取任务信息
        task = tasks.get(task_id)
        if not task:
            app.logger.error(f"任务不存在: {task_id}")
            return jsonify({
                'status': 'error',
                'error': '任务不存在'
            }), 404
            
        # 查找对应的扫描结果
        result = None
        for scan_result in task['scan_results']:
            if scan_result.rule_id == rule_id:
                result = scan_result
                break
                
        if not result:
            app.logger.error(f"未找到指定的漏洞: {rule_id}")
            return jsonify({
                'status': 'error',
                'error': '未找到指定的漏洞'
            }), 404
            
        # 使用AI分析器进行深入分析
        config = db.get_api_config()
        if not config:
            app.logger.error("API配置未设置")
            return jsonify({
                'status': 'error',
                'error': 'API配置未设置，请先配置API信息'
            }), 400
            
        analyzer = AIAnalyzer(
            api_key=config['api_key'],
            api_base=config['api_base'],
            model=config['model']
        )
        
        # 读取合约文件内容
        try:
            with open(task['file_path'], 'r', encoding='utf-8') as f:
                contract_code = f.read()
        except FileNotFoundError:
            app.logger.error(f"合约文件不存在: {task['file_path']}")
            return jsonify({
                'status': 'error',
                'error': '合约文件不存在'
            }), 404
        except Exception as e:
            app.logger.error(f"读取合约文件失败: {str(e)}")
            return jsonify({
                'status': 'error',
                'error': f'读取合约文件失败: {str(e)}'
            }), 500
            
        try:
            analysis_result = asyncio.run(analyzer.analyze_vulnerability(
                result=result,
                contract_code=contract_code
            ))
            
            app.logger.info(f"漏洞分析完成: {vuln_id}")
            return jsonify({
                'status': 'success',
                'analysis': analysis_result.to_dict()
            })
        except Exception as e:
            app.logger.error(f"AI分析过程出错: {str(e)}")
            return jsonify({
                'status': 'error',
                'error': f'AI分析失败: {str(e)}'
            }), 500
            
    except Exception as e:
        app.logger.error(f"分析漏洞时发生未知错误: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': f'分析过程发生未知错误: {str(e)}'
        }), 500

@app.errorhandler(404)
def not_found(error):
    """处理404错误"""
    return jsonify({
        'error': '请求的资源不存在',
        'code': 404
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """处理500错误"""
    return jsonify({
        'error': '服务器内部错误',
        'code': 500
    }), 500

if __name__ == '__main__':
    app.run(debug=True)