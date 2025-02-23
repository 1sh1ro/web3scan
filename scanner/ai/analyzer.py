from typing import List, Dict, Optional
from dataclasses import dataclass
import os
import json
import aiohttp
import asyncio
from ..rules.engine import ScanResult

class AIAnalysisResult:
    def __init__(self, vulnerability_confirmed: bool, confidence_score: float, explanation: str, poc: str = None, remediation: str = None):
        self.vulnerability_confirmed = vulnerability_confirmed
        self.confidence_score = confidence_score
        self.explanation = explanation
        self.poc = poc
        self.remediation = remediation
        
    def to_dict(self) -> dict:
        """将分析结果转换为字典格式"""
        return {
            'vulnerability_confirmed': self.vulnerability_confirmed,
            'confidence_score': self.confidence_score,
            'explanation': self.explanation,
            'poc': self.poc,
            'remediation': self.remediation
        }

class AIAnalyzer:
    def __init__(self, api_key: str = None, api_base: str = None, model: str = "gpt-4"):
        """初始化AI分析器
        
        Args:
            api_key: API密钥，如果不提供则从数据库获取
            api_base: API基础URL，如果不提供则从数据库获取
            model: 使用的AI模型，如果不提供则从数据库获取
        """
        from database import db
        config = db.get_api_config()
        
        self.api_key = api_key or config.get('api_key')
        if not self.api_key:
            raise ValueError('API密钥未设置')
            
        self.api_base = api_base or config.get('api_base', "https://api.openai.com/v1")
        self.model = model or config.get('model', "gpt-4")

    async def analyze_vulnerability(self, result: ScanResult, contract_code: str) -> AIAnalysisResult:
        """第一阶段：AI分析潜在漏洞"""
        prompt = f"""分析以下智能合约代码中的潜在漏洞：

代码片段：
{result.matched_code}

上下文：
{contract_code}

规则匹配：发现可能的{result.severity}级别漏洞

请以'真'或'假'开头回答以下问题：
1. 这是否是一个真实的漏洞？
2. 如果是，漏洞的具体原因是什么？
3. 对合约安全的潜在影响？
不做其他代码的分析，仅仅查看代码中是否存在我提及的漏洞

请确保回答以'真'或'假'开头。"""

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        
        data = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': '你是一个专业的智能合约安全分析专家。'},
                {'role': 'user', 'content': prompt}
            ]
        }

        # 记录非敏感的请求信息
        print(f"[API请求] 正在发送分析请求到AI服务...")

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f'{self.api_base or "https://api.openai.com/v1"}/chat/completions',
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    response_data = await response.json()
                    
                    if response.status != 200:
                        error_msg = response_data.get('error', {}).get('message', '未知错误')
                        print(f"[API错误] 状态码: {response.status}, 错误信息: {error_msg}")
                        raise Exception(f'API请求失败: {error_msg}')
                    
                    print(f"[API响应] 成功接收分析结果")
                    analysis = response_data['choices'][0]['message']['content']
                    
                    # 优化漏洞判断逻辑
                    analysis_lower = analysis.lower()
                    first_word = analysis_lower.strip().split()[0]
                    is_vulnerable = first_word == '真' or first_word == 'true'

                    return AIAnalysisResult(
                        vulnerability_confirmed=is_vulnerable,
                        confidence_score=0.8 if is_vulnerable else 0.2,
                        explanation=analysis
                    )
            except asyncio.TimeoutError:
                print("[API错误] 请求超时")
                raise Exception('API请求超时')
            except Exception as e:
                print(f"[API错误] {str(e)}")
                raise Exception(f'API请求出错: {str(e)}')

    async def generate_poc(self, result: ScanResult, contract_code: str) -> AIAnalysisResult:
        """第二阶段：生成POC和详细报告"""
        if not result:
            return None

        prompt = f"""为以下智能合约漏洞生成POC和修复建议：

漏洞代码：
{result.matched_code}

合约代码：
{contract_code}

请提供：
1. 漏洞利用POC
2. 详细的修复建议
3. 安全最佳实践建议"""

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        
        data = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': '你是一个专业的智能合约安全专家。'},
                {'role': 'user', 'content': prompt}
            ]
        }

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f'{self.api_base or "https://api.openai.com/v1"}/chat/completions',
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    response_data = await response.json()
                    if response.status != 200:
                        raise Exception(f'API请求失败: {response_data.get("error", {}).get("message", "未知错误")}')

                    analysis = response_data['choices'][0]['message']['content']
                    
                    # 优化结果解析逻辑
                    sections = analysis.lower().split('\n')
                    poc_content = ''
                    remediation_content = ''
                    current_section = ''

                    for line in sections:
                        if 'poc:' in line or 'proof of concept:' in line:
                            current_section = 'poc'
                            continue
                        elif '修复建议:' in line or 'remediation:' in line:
                            current_section = 'remediation'
                            continue
                            
                        if current_section == 'poc':
                            poc_content += line + '\n'
                        elif current_section == 'remediation':
                            remediation_content += line + '\n'

                    return AIAnalysisResult(
                        vulnerability_confirmed=True,
                        confidence_score=0.9,
                        explanation=analysis,
                        poc=poc_content.strip() if poc_content else None,
                        remediation=remediation_content.strip() if remediation_content else None
                    )
            except asyncio.TimeoutError:
                raise Exception('API请求超时')
            except Exception as e:
                raise Exception(f'API请求出错: {str(e)}')

    def save_analysis_result(self, result: AIAnalysisResult, output_dir: str, task_id: str):
        """保存分析结果到文件"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        result_file = os.path.join(output_dir, f'{task_id}_analysis.json')
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump({
                'vulnerability_confirmed': result.vulnerability_confirmed,
                'confidence_score': result.confidence_score,
                'explanation': result.explanation,
                'poc': result.poc,
                'remediation': result.remediation
            }, f, ensure_ascii=False, indent=2)
    async def convert_to_rule(self, description: str, target_langs: List[str] = None) -> Dict:
        """将自然语言描述转换为规则JSON格式
        
        Args:
            description: 规则的自然语言描述
            target_langs: 目标编程语言列表
            
        Returns:
            规则的JSON格式数据
        """
        prompt = f"""请将以下自然语言描述的安全规则转换为JSON格式：

规则描述：
{description}

目标语言：{', '.join(target_langs) if target_langs else '通用'}

请生成包含以下字段的JSON格式规则：
1. id: 规则唯一标识符，如"SOL-101"，具体看对应的语言前缀
2. name: 规则名称
3. description: 规则描述
4. pattern: 匹配模式
5. severity: 严重程度(high/medium/low)
6. category: 漏洞类别
7. target_langs: 目标语言列表（如果指定）
8. lang_specific_patterns: 语言特定的匹配模式（如果需要）"""

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        
        data = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': '你是一个专业的安全规则转换专家。'},
                {'role': 'user', 'content': prompt}
            ]
        }

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f'{self.api_base or "https://api.openai.com/v1"}/chat/completions',
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    response_data = await response.json()
                    if response.status != 200:
                        raise Exception(f'API请求失败: {response_data.get("error", {}).get("message", "未知错误")}')

                    # 解析AI生成的规则JSON
                    rule_json = response_data['choices'][0]['message']['content']
                    try:
                        # 尝试解析JSON字符串
                        rule_dict = json.loads(rule_json)
                        # 验证必要字段
                        required_fields = ['id', 'name', 'description', 'pattern', 'severity', 'category']
                        for field in required_fields:
                            if field not in rule_dict:
                                raise ValueError(f'规则缺少必要字段: {field}')
                        return rule_dict
                    except json.JSONDecodeError:
                        raise Exception('AI生成的规则格式无效')
            except asyncio.TimeoutError:
                raise Exception('API请求超时')
            except Exception as e:
                raise Exception(f'转换规则时出错: {str(e)}')

    async def convert_to_rule(self, vuln_description: str, target_langs: List[str] = None) -> Dict:
        """将自然语言描述转换为规则格式
        
        Args:
            vuln_description: 规则的自然语言描述
            target_langs: 目标编程语言列表
            
        Returns:
            Dict: 规则的JSON格式
        """
        prompt = f"""请将以下漏洞描述总结出他的安全规则，并转换为结构化的规则定义：

漏洞描述：
{vuln_description}

目标语言：{', '.join(target_langs) if target_langs else '通用'}

请生成包含以下字段的JSON格式规则：
- id: 规则唯一标识符，sol就用“SOL”开头，go就用“GO”开头，rust就用“RUST”开头
- name: 规则名称（简短描述）
- description: 详细描述
- pattern: 正则表达式模式
- severity: critical/high/medium/low
- category: 漏洞类别
- target_langs: 目标语言列表
- lang_specific_patterns: 语言特定的匹配模式

请确保返回的是一个有效的JSON字符串，不要包含任何额外的说明文字。"""

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        
        data = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': '你是一个专业的代码安全分析专家，请只返回JSON格式的规则定义，不要包含任何其他文字。'},
                {'role': 'user', 'content': prompt}
            ]
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f'{self.api_base or "https://api.openai.com/v1"}/chat/completions',
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    response_data = await response.json()
                    if response.status != 200:
                        raise Exception(f'API请求失败: {response_data.get("error", {}).get("message", "未知错误")}')

                    content = response_data['choices'][0]['message']['content'].strip()
                    
                    # 预处理AI返回的内容
                    try:
                        # 尝试提取JSON部分，使用更可靠的正则表达式
                        import re
                        # 更新正则表达式以处理嵌套的JSON结构
                        json_match = re.search(r'\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}', content)
                        if json_match:
                            content = json_match.group()
                            # 清理可能的格式问题
                            content = re.sub(r'\s+', ' ', content)  # 规范化空白字符
                            content = re.sub(r',\s*}', '}', content)  # 移除尾随逗号
                            content = re.sub(r',\s*]', ']', content)  # 移除数组中的尾随逗号
                        else:
                            raise ValueError('无法从返回内容中提取有效的JSON对象')
                        
                        try:
                            rule_json = json.loads(content)
                        except json.JSONDecodeError as je:
                            # 尝试修复常见的JSON格式问题
                            content = content.replace('\'', '"')  # 替换单引号
                            content = re.sub(r'"([^"]+)"\s*:', r'"\1":', content)  # 修复键值对格式
                            rule_json = json.loads(content)
                        
                        # 验证必要字段
                        required_fields = ['id', 'name', 'description', 'pattern', 'severity', 'category']
                        missing_fields = [field for field in required_fields if field not in rule_json]
                        if missing_fields:
                            raise ValueError(f'规则缺少必要字段: {", ".join(missing_fields)}')
                        
                        # 确保规则有唯一ID
                        if 'id' not in rule_json:
                            import uuid
                            rule_json['id'] = str(uuid.uuid4())
                        
                        # 添加目标语言
                        if target_langs:
                            rule_json['target_langs'] = target_langs
                        
                        # 验证字段值的有效性
                        if not isinstance(rule_json['pattern'], str):
                            raise ValueError('pattern字段必须是字符串类型')
                        if rule_json['severity'] not in ['critical', 'high', 'medium', 'low']:
                            raise ValueError('severity字段值无效')
                        
                        return rule_json
                    except json.JSONDecodeError as e:
                        print(f"JSON解析错误: {str(e)}\nAI返回内容: {content}")
                        raise Exception(f'JSON解析失败: {str(e)}')
                    except ValueError as ve:
                        print(f"数据验证错误: {str(ve)}\nAI返回内容: {content}")
                        raise Exception(f'规则验证失败: {str(ve)}')
                    except Exception as e:
                        print(f"处理AI返回内容时出错: {str(e)}\nAI返回内容: {content}")
                        raise Exception(f'规则处理失败: {str(e)}')

        except Exception as e:
            print(f"转换规则时出错: {e}")
            raise

class AICodeAnalyzer:
    def __init__(self, api_key: str = None, api_base: str = None, model: str = "gpt-4"):
        """初始化AI代码分析器
        
        Args:
            api_key: API密钥，如果不提供则从数据库获取
            api_base: API基础URL，如果不提供则从数据库获取
            model: 使用的AI模型，如果不提供则从数据库获取
        """
        from database import db
        config = db.get_api_config()
        
        self.api_key = api_key or config.get('api_key')
        if not self.api_key:
            raise ValueError('API密钥未设置')
            
        self.api_base = api_base or config.get('api_base', "https://api.openai.com/v1")
        self.model = model or config.get('model', "gpt-4")

    async def analyze(self, code: str, lang: str) -> Dict:
        """分析代码并生成AST
        
        Args:
            code: 要分析的代码
            lang: 编程语言
            
        Returns:
            Dict: 包含AST和分析结果的字典
        """
        prompt = f"""请详细分析以下{lang}代码并生成抽象语法树（AST）和相关分析：

代码：
{code}

请提供以下详细信息（JSON格式）：
1. ast: 完整的抽象语法树结构，包含：
   - 节点类型
   - 节点值
   - 子节点
   - 代码位置信息
2. semantic_info:
   - 变量定义和使用
   - 函数调用关系
   - 类型信息
3. vulnerabilities: 潜在的安全漏洞列表
4. patterns: 代码模式分析
   - 常量定义
   - 函数定义
   - 特定API调用
5. data_flow: 数据流分析
   - 变量传播路径
   - 值依赖关系

请确保返回格式化的JSON数据。"""

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        
        data = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': '你是一个专业的代码分析专家，精通AST分析。'},
                {'role': 'user', 'content': prompt}
            ]
        }

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f'{self.api_base or "https://api.openai.com/v1"}/chat/completions',
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    response_data = await response.json()
                    if response.status != 200:
                        raise Exception(f'API请求失败: {response_data.get("error", {}).get("message", "未知错误")}')
                    
                    analysis = response_data['choices'][0]['message']['content']
                    
                    # 解析AI返回的分析结果
                    try:
                        ast_data = json.loads(analysis)
                        # 验证返回的数据结构
                        required_fields = ['ast', 'semantic_info', 'vulnerabilities', 'patterns', 'data_flow']
                        for field in required_fields:
                            if field not in ast_data:
                                ast_data[field] = {}
                        return ast_data
                    except json.JSONDecodeError:
                        print("AI返回的结果不是有效的JSON格式")
                        return {}
                    except Exception as e:
                        print(f"解析AI返回结果时出错: {e}")
                        return {}

            except Exception as e:
                print(f"AI分析过程出错: {e}")
                return {}

    def _parse_ai_response(self, analysis: str) -> Dict:
        """解析AI返回的分析结果"""
        try:
            # 尝试直接解析JSON格式的响应
            if analysis.strip().startswith('{'):
                return json.loads(analysis)
            
            # 如果不是JSON格式，进行结构化解析
            sections = analysis.split('\n\n')
            ast_data = {
                'ast': {},
                'semantic_info': {},
                'vulnerabilities': [],
                'patterns': {'unsafe': [], 'safe': []},
                'data_flow': {}
            }
            
            current_section = ''
            current_content = []
            
            for section in sections:
                if section.lower().startswith('ast') or 'abstract syntax tree' in section.lower():
                    current_section = 'ast'
                    current_content = []
                elif '语义' in section or 'semantic' in section.lower():
                    current_section = 'semantic'
                    current_content = []
                elif '漏洞' in section or 'vulnerability' in section.lower():
                    current_section = 'vulnerability'
                    current_content = []
                elif '模式' in section or 'pattern' in section.lower():
                    current_section = 'pattern'
                    current_content = []
                elif '数据流' in section or 'data flow' in section.lower():
                    current_section = 'data_flow'
                    current_content = []
                else:
                    current_content.append(section)
                    
                if current_section == 'ast':
                    ast_data['ast'] = self._parse_ast_section('\n'.join(current_content))
                elif current_section == 'semantic':
                    ast_data['semantic_info'] = self._parse_semantic_section('\n'.join(current_content))
                elif current_section == 'vulnerability':
                    ast_data['vulnerabilities'] = self._parse_vulnerability_section('\n'.join(current_content))
                elif current_section == 'pattern':
                    ast_data['patterns'] = self._parse_pattern_section('\n'.join(current_content))
                elif current_section == 'data_flow':
                    ast_data['data_flow'] = self._parse_data_flow_section('\n'.join(current_content))
                    
            return ast_data
            
        except Exception as e:
            print(f"解析AI响应时出错: {e}")
            return {}
            
    def _parse_ast_section(self, content: str) -> Dict:
        """解析AST部分"""
        try:
            # 尝试提取JSON格式的AST
            import re
            json_match = re.search(r'\{[^}]+\}', content)
            if json_match:
                return json.loads(json_match.group())
            return {'nodes': self._extract_nodes(content)}
        except:
            return {'raw': content}
            
    def _parse_semantic_section(self, content: str) -> Dict:
        """解析语义信息部分"""
        return {'analysis': content}
        
    def _parse_vulnerability_section(self, content: str) -> List:
        """解析漏洞信息部分"""
        vulns = []
        for line in content.split('\n'):
            if line.strip():
                vulns.append({'description': line.strip()})
        return vulns
        
    def _parse_pattern_section(self, content: str) -> Dict:
        """解析代码模式部分"""
        patterns = {'unsafe': [], 'safe': []}
        current_type = 'unsafe'
        
        for line in content.split('\n'):
            if '安全' in line or 'safe' in line.lower():
                current_type = 'safe'
            elif '不安全' in line or 'unsafe' in line.lower():
                current_type = 'unsafe'
            elif line.strip():
                patterns[current_type].append({'pattern': line.strip()})
                
        return patterns
        
    def _parse_data_flow_section(self, content: str) -> Dict:
        """解析数据流部分"""
        return {'analysis': content}
        
    def _extract_nodes(self, content: str) -> List:
        """从文本内容中提取节点信息"""
        nodes = []
        for line in content.split('\n'):
            if line.strip():
                nodes.append({'content': line.strip()})
        return nodes
    async def analyze_ast(self, code: str, lang: str) -> Dict:
        """分析代码的AST结构
        
        Args:
            code: 源代码
            lang: 编程语言
            
        Returns:
            AST分析结果
        """
        prompt = f"""分析以下{lang}代码的AST结构，重点关注：

1. 函数调用和参数
2. 变量声明和赋值
3. 控制流结构
4. 类型定义
5. 特殊语言结构（如Go的defer、goroutine等）

代码：
{code}

请提供详细的AST分析结果，包括：
1. 节点类型和属性
2. 数据流信息
3. 控制流图
4. 类型信息
5. 符号表"""

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
        
        data = {
            'model': self.model,
            'messages': [
                {'role': 'system', 'content': '你是一个专业的代码分析专家。'},
                {'role': 'user', 'content': prompt}
            ]
        }

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f'{self.api_base}/chat/completions',
                    headers=headers,
                    json=data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    response_data = await response.json()
                    if response.status != 200:
                        raise Exception(f'API请求失败: {response_data.get("error", {}).get("message", "未知错误")}')

                    analysis = response_data['choices'][0]['message']['content']
                    
                    # 解析AI返回的AST分析结果
                    try:
                        ast_data = json.loads(analysis)
                        return {
                            'ast': ast_data.get('ast', {}),
                            'data_flow': ast_data.get('data_flow', {}),
                            'control_flow': ast_data.get('control_flow', {}),
                            'type_info': ast_data.get('type_info', {}),
                            'symbol_table': ast_data.get('symbol_table', {})
                        }
                    except json.JSONDecodeError:
                        # 如果返回结果不是JSON格式，进行结构化处理
                        return self._parse_ast_analysis(analysis)
            except Exception as e:
                print(f"AST分析出错: {e}")
                return {}

    def _parse_ast_analysis(self, analysis: str) -> Dict:
        """解析非JSON格式的AST分析结果"""
        result = {
            'ast': {},
            'data_flow': {},
            'control_flow': {},
            'type_info': {},
            'symbol_table': {}
        }
        
        # 使用正则表达式提取各部分信息
        import re
        
        # 提取AST节点信息
        ast_matches = re.finditer(r'节点类型:\s*([\w_]+)\s*属性:\s*({[^}]+})', analysis)
        for match in ast_matches:
            node_type = match.group(1)
            attrs = match.group(2)
            result['ast'][node_type] = self._parse_attributes(attrs)
            
        # 提取数据流信息
        data_flow_match = re.search(r'数据流信息:\s*({[^}]+})', analysis)
        if data_flow_match:
            result['data_flow'] = self._parse_attributes(data_flow_match.group(1))
            
        # 提取控制流信息
        control_flow_match = re.search(r'控制流图:\s*({[^}]+})', analysis)
        if control_flow_match:
            result['control_flow'] = self._parse_attributes(control_flow_match.group(1))
            
        # 提取类型信息
        type_info_match = re.search(r'类型信息:\s*({[^}]+})', analysis)
        if type_info_match:
            result['type_info'] = self._parse_attributes(type_info_match.group(1))
            
        # 提取符号表
        symbol_table_match = re.search(r'符号表:\s*({[^}]+})', analysis)
        if symbol_table_match:
            result['symbol_table'] = self._parse_attributes(symbol_table_match.group(1))
            
        return result
        
    def _parse_attributes(self, attrs_str: str) -> Dict:
        """解析属性字符串为字典格式"""
        try:
            # 清理和规范化属性字符串
            attrs_str = attrs_str.replace("'", '"')
            return json.loads(attrs_str)
        except json.JSONDecodeError:
            # 如果无法解析为JSON，使用简单的键值对解析
            attrs = {}
            pairs = re.finditer(r'(\w+)\s*[:=]\s*([^,}]+)', attrs_str)
            for pair in pairs:
                key = pair.group(1).strip()
                value = pair.group(2).strip()
                attrs[key] = value
            return attrs