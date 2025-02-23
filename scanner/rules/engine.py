from typing import Dict, Type, List
from dataclasses import dataclass, field
import os
import json
import logging
import re

@dataclass
class Rule:
    """漏洞规则定义"""
    id: str
    name: str
    description: str
    pattern: str
    severity: str
    category: str

@dataclass
class ScanResult:
    """扫描结果"""
    rule_id: str
    file_path: str
    line_number: int
    matched_code: str
    severity: str

@dataclass
class PolyglotRule(Rule):
    """多语言规则定义"""
    target_langs: List[str] = field(default_factory=list)  # 支持语言列表
    lang_specific_patterns: Dict[str, str] = field(default_factory=dict)  # 语言特定模式

@dataclass
class RuleEngine:
    """规则引擎基类"""
    rules_dir: str = 'rules'
    rules: List[Rule] = field(default_factory=list)

    def __init__(self, rules_dir: str = 'rules'):
        self.rules_dir = rules_dir
        self.rules = []
        self.load_rules()  # 确保在初始化时加载规则

    def load_rules(self):
        """加载规则"""
        rule_files = {
            'go': os.path.join(self.rules_dir, 'go_rules.json'),
            'rust': os.path.join(self.rules_dir, 'rust_rules.json'),
            'sol': os.path.join(self.rules_dir, 'sol_rules.json')
        }
        
        for file_path in rule_files.values():
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for rule_data in data.get('rules', []):
                        rule = PolyglotRule(
                            id=rule_data['id'],
                            name=rule_data['name'],
                            description=rule_data['description'],
                            pattern=rule_data['pattern'],
                            severity=rule_data['severity'],
                            category=rule_data['category'],
                            target_langs=rule_data.get('target_langs', []),
                            lang_specific_patterns=rule_data.get('lang_specific_patterns', {})
                        )
                        self.rules.append(rule)

    def _save_rule_to_file(self, rule: Rule, file_path: str):
        """将规则保存到指定的JSON文件中"""
        # 读取现有规则
        existing_rules = []
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    existing_rules = data.get('rules', [])
                except json.JSONDecodeError:
                    print(f"无法解析规则文件: {file_path}")
                    return
        
        # 转换规则为字典格式
        rule_dict = {
            'id': rule.id,
            'name': rule.name,
            'description': rule.description,
            'pattern': rule.pattern,
            'severity': rule.severity,
            'category': rule.category
        }
        
        if isinstance(rule, PolyglotRule):
            rule_dict.update({
                'target_langs': rule.target_langs,
                'lang_specific_patterns': rule.lang_specific_patterns
            })
        
        # 检查是否已存在相同ID的规则，如果存在则更新
        for i, existing_rule in enumerate(existing_rules):
            if existing_rule['id'] == rule.id:
                existing_rules[i] = rule_dict
                break
        else:
            existing_rules.append(rule_dict)
        
        # 保存更新后的规则
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump({'rules': existing_rules}, f, ensure_ascii=False, indent=4)

    def add_rule(self, rule: Rule):
        """添加新规则并持久化到对应的规则文件中"""
        self.rules.append(rule)
        
        # 根据规则ID前缀确定目标语言
        rule_id = rule.id
        if rule_id.startswith('GO-'):
            file_path = os.path.join(self.rules_dir, 'go_rules.json')
        elif rule_id.startswith('RUST-'):
            file_path = os.path.join(self.rules_dir, 'rust_rules.json')
        elif rule_id.startswith('SOL-'):
            file_path = os.path.join(self.rules_dir, 'sol_rules.json')
        else:
            # 如果规则ID前缀不匹配任何已知语言，使用target_langs中的第一个语言
            if isinstance(rule, PolyglotRule) and rule.target_langs:
                lang = rule.target_langs[0]
                file_path = os.path.join(self.rules_dir, f'{lang}_rules.json')
            else:
                # 如果没有目标语言信息，保存到通用规则文件
                file_path = os.path.join(self.rules_dir, 'common_rules.json')
        
        self._save_rule_to_file(rule, file_path)
    
    async def scan_file(self, file_path: str) -> List[ScanResult]:
        """扫描文件，使用AST分析进行更精确的代码检测"""
        results = []
        try:
            # 读取文件内容
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # 获取文件扩展名和语言类型
            file_ext = os.path.splitext(file_path)[1].lower()
            lang = file_ext[1:] if file_ext else ''
            
            # 根据文件类型选择适用的规则
            applicable_rules = [rule for rule in self.rules 
                              if lang in rule.target_langs]
            
            # 使用AI代码分析器进行AST分析
            try:
                from ..ai.analyzer import AICodeAnalyzer
                analyzer = AICodeAnalyzer()
                ast_analysis = await analyzer.analyze(content, lang)
                
                # 基于AST分析结果进行规则匹配
                for rule in applicable_rules:
                    # 检查AST中的漏洞
                    for vuln in ast_analysis.get('vulnerabilities', []):
                        if vuln.get('type') == rule.id:
                            results.append(ScanResult(
                                rule_id=rule.id,
                                file_path=file_path,
                                line_number=vuln.get('line', 0),
                                matched_code=vuln.get('code', ''),
                                severity=rule.severity
                            ))
                    
                    # 检查不安全的代码模式
                    for pattern in ast_analysis.get('patterns', {}).get('unsafe', []):
                        results.append(ScanResult(
                            rule_id=rule.id,
                            file_path=file_path,
                            line_number=pattern.get('line', 0),
                            matched_code=pattern.get('code', ''),
                            severity=rule.severity
                        ))
                        
                    # 分析数据流中的安全问题
                    for flow in ast_analysis.get('data_flow', {}).get('unsafe_flows', []):
                        results.append(ScanResult(
                            rule_id=rule.id,
                            file_path=file_path,
                            line_number=flow.get('line', 0),
                            matched_code=flow.get('code', ''),
                            severity=rule.severity
                        ))
                        
            except ImportError:
                print("AI分析器未找到，回退到基础模式扫描")
                # 如果AI分析器不可用，回退到基础的模式匹配
                for rule in applicable_rules:
                    pattern = rule.lang_specific_patterns.get(
                        lang.capitalize(),
                        rule.pattern
                    )
                    if pattern:
                        matches = re.finditer(pattern, content, re.MULTILINE)
                        for match in matches:
                            results.append(ScanResult(
                                rule_id=rule.id,
                                file_path=file_path,
                                line_number=content.count('\n', 0, match.start()) + 1,
                                matched_code=match.group(),
                                severity=rule.severity
                            ))
                        
        except Exception as e:
            logging.error(f"扫描文件 {file_path} 时出错: {str(e)}")
            
        return results
        
    def scan_contract(self, file_path: str) -> List[ScanResult]:
        """扫描智能合约文件
        
        Args:
            file_path: 合约文件路径
            
        Returns:
            扫描结果列表
        """
        return self.scan_file(file_path)

    def get_rules(self) -> List[Rule]:
        """获取所有规则"""
        return self.rules

    def add_rule(self, rule: Rule):
        """添加新规则"""
        self.rules.append(rule)
        # TODO: 将新规则持久化到对应的规则文件中

    async def add_rule_from_description(self, rule_description: str, target_langs: List[str] = None, api_key: str = None, api_base: str = None, model: str = None) -> Rule:
        """从自然语言描述添加新规则"""
        try:
            from ..ai.analyzer import AIAnalyzer
            ai_analyzer = AIAnalyzer(api_key=api_key, api_base=api_base, model=model)
            # 调用AI服务将自然语言转换为规则
            rule_json = await ai_analyzer.convert_to_rule(rule_description, target_langs)
            
            # 如果target_langs为空，根据规则ID前缀判断目标语言
            if not target_langs:
                rule_id = rule_json['id']
                if rule_id.startswith('GO-'):
                    target_langs = ['go']
                elif rule_id.startswith('RUST-'):
                    target_langs = ['rust']
                elif rule_id.startswith('SOL-'):
                    target_langs = ['sol']
            
            # 创建规则对象
            if target_langs:
                rule = PolyglotRule(
                    id=rule_json['id'],
                    name=rule_json['name'],
                    description=rule_json['description'],
                    pattern=rule_json['pattern'],
                    severity=rule_json['severity'],
                    category=rule_json['category'],
                    target_langs=target_langs,
                    lang_specific_patterns=rule_json.get('lang_specific_patterns', {})
                )
                # 添加规则并持久化到对应语言的规则文件
                self.rules.append(rule)
                for lang in target_langs:
                    file_path = os.path.join(self.rules_dir, f'{lang}_rules.json')
                    self._save_rule_to_file(rule, file_path)
            else:
                # 如果无法判断目标语言，创建通用规则
                rule = Rule(
                    id=rule_json['id'],
                    name=rule_json['name'],
                    description=rule_json['description'],
                    pattern=rule_json['pattern'],
                    severity=rule_json['severity'],
                    category=rule_json['category']
                )
                # 添加规则并持久化到通用规则文件
                self.rules.append(rule)
                file_path = os.path.join(self.rules_dir, 'common_rules.json')
                self._save_rule_to_file(rule, file_path)
                
            return rule
                    
        except ImportError:
            print("AI分析器未找到，无法转换规则")
            return None
        except Exception as e:
            print(f"转换规则时出错: {e}")
            return None

# 动态导入解析器
def import_parser(name: str):
    try:
        if name == 'rust':
            import rust_parser
            return rust_parser.parse
        elif name == 'go':
            import go_ast
            return go_ast.parse
        elif name == 'sol':
            import solidity_parser
            return solidity_parser.parse
    except ImportError:
        return None

@dataclass
class PolyglotEngine(RuleEngine):
    def _load_rules_from_json(self, file_path: str) -> List[PolyglotRule]:
        """从JSON文件加载规则"""
        if not os.path.exists(file_path):
            return []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        rules = []
        for rule_data in data.get('rules', []):
            rule = PolyglotRule(
                id=rule_data['id'],
                name=rule_data['name'],
                description=rule_data['description'],
                pattern=rule_data['pattern'],
                severity=rule_data['severity'],
                category=rule_data['category'],
                target_langs=rule_data.get('target_langs', []),
                lang_specific_patterns=rule_data.get('lang_specific_patterns', {})
            )
            rules.append(rule)
        return rules

    def __init__(self, rules_dir: str = 'rules'):
        super().__init__(rules_dir)
        self.rules = []
        # 加载各语言的规则
        rule_files = {
            'go': os.path.join(rules_dir, 'go_rules.json'),
            'rust': os.path.join(rules_dir, 'rust_rules.json'),
            'sol': os.path.join(rules_dir, 'sol_rules.json')
        }
        
        for file_path in rule_files.values():
            self.rules.extend(self._load_rules_from_json(file_path))
        
        self.parsers = {}
        self._init_parsers()

    def _init_parsers(self):
        """初始化可用的语言解析器"""
        for lang in ['go', 'rust', 'sol']:
            if parser := import_parser(lang):
                self.parsers[lang] = parser

    def _detect_language(self, file_path: str) -> str:
        """自动检测编程语言"""
        if file_path.endswith('.go'):
            return 'go'
        elif file_path.endswith('.rs'):
            return 'rust'
        elif file_path.endswith('.sol'):
            return 'sol'
        return 'unknown'

    async def _analyze_by_lang(self, code: str, lang: str) -> Dict:
        """语言专用分析器"""
        ast = {}
        if parser := self.parsers.get(lang):
            try:
                # 使用语言特定解析器获取基础AST
                ast = parser(code)
                
                # 使用AI增强AST分析
                try:
                    from ..ai.analyzer import AICodeAnalyzer
                    ai_analyzer = AICodeAnalyzer()
                    ai_ast = await ai_analyzer.analyze(code, lang)
                    
                    # 合并AI分析结果到AST
                    ast.update({
                        'ai_analysis': {
                            'ast': ai_ast.get('ast', {}),
                            'semantic_info': ai_ast.get('semantic_info', {}),
                            'potential_vulnerabilities': ai_ast.get('vulnerabilities', []),
                            'code_patterns': ai_ast.get('patterns', {}),
                            'data_flow': ai_ast.get('data_flow', {})
                        }
                    })
                except ImportError:
                    print("AI分析器未找到，仅使用基础AST分析")
                except Exception as e:
                    print(f"AI分析过程出错: {e}")
                    
                return ast
            except Exception as e:
                print(f"解析{lang}代码时出错: {e}")
        return ast

    def _lang_specific_checks(self, ast: Dict, rule: PolyglotRule, lang: str) -> List[ScanResult]:
        """基于AST的语言专用漏洞检测"""
        findings = []
        
        # 获取AI分析结果
        ai_analysis = ast.get('ai_analysis', {})
        potential_vulns = ai_analysis.get('potential_vulnerabilities', [])
        code_patterns = ai_analysis.get('code_patterns', {})
        semantic_info = ai_analysis.get('semantic_info', {})
        data_flow = ai_analysis.get('data_flow', {})
        
        # 根据语言和规则ID执行特定检查
        if lang == 'go':
            if rule.id == "MORPH-001":
                findings.extend(self._check_go_batch_limit(ast, rule))
            # 检查AI发现的潜在漏洞
            findings.extend(self._check_ai_findings(potential_vulns, rule))
            # 分析不安全的代码模式
            findings.extend(self._analyze_unsafe_patterns(code_patterns, rule))
            
        elif lang == 'rust':
            if rule.id == "RUST-001":
                findings.extend(self._check_unsafe_blocks(ast, rule))
            # 分析AI识别的不安全代码模式
            findings.extend(self._analyze_unsafe_patterns(code_patterns, rule))
            # 分析数据流中的潜在问题
            findings.extend(self._analyze_data_flow(data_flow, rule))
        
        # 使用语义信息进行额外检查
        findings.extend(self._check_semantic_issues(semantic_info, rule))
        
        return findings

    def _check_semantic_issues(self, semantic_info: Dict, rule: PolyglotRule) -> List[ScanResult]:
        """检查语义相关的安全问题"""
        findings = []
        for issue in semantic_info.get('issues', []):
            if issue.get('type') == rule.id:
                findings.append(ScanResult(
                    rule_id=rule.id,
                    file_path=issue.get('file', ''),
                    line_number=issue.get('line', 0),
                    matched_code=issue.get('code', ''),
                    severity=rule.severity
                ))
        return findings

    def _analyze_data_flow(self, data_flow: Dict, rule: PolyglotRule) -> List[ScanResult]:
        """分析数据流中的安全问题"""
        findings = []
        for flow in data_flow.get('unsafe_flows', []):
            findings.append(ScanResult(
                rule_id=rule.id,
                file_path=flow.get('file', ''),
                line_number=flow.get('line', 0),
                matched_code=flow.get('code', ''),
                severity=rule.severity
            ))
        return findings

    def _check_ai_findings(self, potential_vulns: List[Dict], rule: PolyglotRule) -> List[ScanResult]:
        """分析AI发现的潜在漏洞"""
        findings = []
        for vuln in potential_vulns:
            if vuln.get('type') == rule.id:
                findings.append(ScanResult(
                    rule_id=rule.id,
                    file_path=vuln.get('file', ''),
                    line_number=vuln.get('line', 0),
                    matched_code=vuln.get('code', ''),
                    severity=rule.severity
                ))
        return findings

    def _analyze_unsafe_patterns(self, ai_analysis: Dict, rule: PolyglotRule) -> List[ScanResult]:
        """分析AI识别的不安全代码模式"""
        findings = []
        patterns = ai_analysis.get('code_patterns', {})
        
        for pattern in patterns.get('unsafe', []):
            findings.append(ScanResult(
                rule_id=rule.id,
                file_path=pattern.get('file', ''),
                line_number=pattern.get('line', 0),
                matched_code=pattern.get('code', ''),
                severity=rule.severity
            ))
        return findings

    async def scan_file(self, file_path: str) -> List[ScanResult]:
        """多语言文件扫描"""
        lang = self._detect_language(file_path)
        with open(file_path, 'r') as f:
            code = f.read()
        
        ast = await self._analyze_by_lang(code, lang)
        results = []
        
        for rule in self.rules:
            if not isinstance(rule, PolyglotRule) or lang not in rule.target_langs:
                continue
                
            # 执行语言专用检测逻辑
            if findings := self._lang_specific_checks(ast, rule, lang):
                results.extend(findings)
            
            # 跨语言通用模式检测
            if matches := self._cross_lang_pattern_scan(code, rule, lang):
                results.extend(matches)
        
        return results

    def _cross_lang_pattern_scan(self, code: str, rule: PolyglotRule, lang: str) -> List[ScanResult]:
        """跨语言通用模式检测，基于AST分析"""
        results = []
        if pattern := rule.lang_specific_patterns.get(lang):
            # 使用AST分析器获取代码的AST结构
            ast = self.parsers.get(lang, lambda x: {})(code)
            
            # 从AST中提取相关节点
            node_types = [
                'const_decls',      # 常量声明
                'function_calls',   # 函数调用
                'patterns',         # 代码模式
                'var_decls',       # 变量声明
                'type_decls',      # 类型声明
                'struct_decls',    # 结构体声明
                'interface_decls', # 接口声明
                'method_decls',    # 方法声明
                'imports',         # 导入语句
                'assignments'      # 赋值语句
            ]
            
            # 遍历所有节点类型
            for node_type in node_types:
                if node_type in ast:
                    for node in ast[node_type]:
                        # 增强的AST模式匹配
                        if self._match_ast_pattern(node, pattern):
                            results.append(self._create_result_from_node(node, rule))
                            
            # 分析特殊语言结构
            if lang == 'go':
                # 分析Go特有的语言结构
                special_nodes = ['defer_stmts', 'go_stmts', 'select_stmts']
                for node_type in special_nodes:
                    if node_type in ast:
                        for node in ast[node_type]:
                            if self._match_ast_pattern(node, pattern):
                                results.append(self._create_result_from_node(node, rule))
            elif lang == 'rust':
                # 分析Rust特有的语言结构
                special_nodes = ['unsafe_blocks', 'macro_calls', 'trait_impls']
                for node_type in special_nodes:
                    if node_type in ast:
                        for node in ast[node_type]:
                            if self._match_ast_pattern(node, pattern):
                                results.append(self._create_result_from_node(node, rule))
            elif lang == 'sol':
                # 分析Solidity特有的语言结构
                special_nodes = ['contract_decls', 'event_decls', 'modifier_decls']
                for node_type in special_nodes:
                    if node_type in ast:
                        for node in ast[node_type]:
                            if self._match_ast_pattern(node, pattern):
                                results.append(self._create_result_from_node(node, rule))
        
        return results

    def _match_ast_pattern(self, node: Dict, pattern: str) -> bool:
        """匹配AST节点与规则模式"""
        # 检查节点类型和值是否匹配模式
        node_type = node.get('type', '')
        node_value = node.get('value', '')
        node_name = node.get('name', '')
        
        # 尝试多种匹配方式
        try:
            import re
            if re.search(pattern, str(node_value)) or \
               re.search(pattern, str(node_name)) or \
               re.search(pattern, str(node_type)):
                return True
        except Exception:
            pass
            
        return False
        
    def _create_result_from_node(self, node: Dict, rule: PolyglotRule) -> ScanResult:
        """从AST节点创建扫描结果"""
        return ScanResult(
            rule_id=rule.id,
            file_path=node.get('file', ''),
            line_number=node.get('line', 0),
            matched_code=node.get('code', ''),
            severity=rule.severity
        )

    def _create_go_result(self, node: Dict, rule: PolyglotRule) -> ScanResult:
        """创建Go语言扫描结果"""
        return ScanResult(
            rule_id=rule.id,
            file_path=node.get('file', ''),
            line_number=node.get('line', 0),
            matched_code=node.get('code', ''),
            severity=rule.severity
        )

    def _check_unsafe_blocks(self, ast: Dict, rule: PolyglotRule) -> List[ScanResult]:
        """检测Rust不安全代码块"""
        findings = []
        for block in ast.get('unsafe_blocks', []):
            findings.append(ScanResult(
                rule_id=rule.id,
                file_path=block.get('file', ''),
                line_number=block.get('line', 0),
                matched_code=block.get('code', ''),
                severity=rule.severity
            ))
        return findings

    def _lang_specific_checks(self, ast: Dict, rule: PolyglotRule, lang: str) -> List[ScanResult]:
        """语言专用漏洞检测"""
        if lang == 'go':
            # 检测go语言批处理漏洞[^6]
            if rule.id == "MORPH-001":
                return self._check_go_batch_limit(ast, rule)
            
        elif lang == 'rust':
            # Rust内存安全检测示例
            if rule.id == "RUST-001":
                return self._check_unsafe_blocks(ast, rule)
        
        return []

    def _check_go_batch_limit(self, ast: Dict, rule: PolyglotRule) -> List[ScanResult]:
        """检测GO批处理大小限制漏洞[^6]"""
        findings = []
        # 扫描MaxBlocksPerChunk常量定义
        for node in ast.get('const_decls', []):
            if node['name'] == 'MaxBlocksPerChunk' and node['value'] > 100:
                findings.append(self._create_go_result(node, rule))
        
        # 检查相关函数调用
        for call in ast.get('function_calls', []):
            if call['func'] == 'makeBatch' and 'chunkSize' in call['args']:
                findings.append(self._create_go_result(call, rule))
        
        return findings

async def add_rule_from_description(self, rule_description: str, target_langs: List[str] = None, api_key: str = None, api_base: str = None , model : str =None) -> Rule:
    """从自然语言描述添加新规则"""
    try:
        from ..ai.analyzer import AIAnalyzer
        ai_analyzer = AIAnalyzer(api_key=api_key, api_base=api_base,model=model)
        # 调用AI服务将自然语言转换为规则
        rule_json = await ai_analyzer.convert_to_rule(rule_description, target_langs)
        
        # 如果target_langs为空，根据规则ID前缀判断目标语言
        if not target_langs:
            rule_id = rule_json['id']
            if rule_id.startswith('GO-'):
                target_langs = ['go']
            elif rule_id.startswith('RUST-'):
                target_langs = ['rust']
            elif rule_id.startswith('SOL-'):
                target_langs = ['sol']
        
        # 创建规则对象
        if target_langs:
            rule = PolyglotRule(
                id=rule_json['id'],
                name=rule_json['name'],
                description=rule_json['description'],
                pattern=rule_json['pattern'],
                severity=rule_json['severity'],
                category=rule_json['category'],
                target_langs=target_langs,
                lang_specific_patterns=rule_json.get('lang_specific_patterns', {})
            )
            # 添加规则并持久化到对应语言的规则文件
            self.rules.append(rule)
            for lang in target_langs:
                file_path = os.path.join(self.rules_dir, f'{lang}_rules.json')
                self._save_rule_to_file(rule, file_path)
        else:
            # 如果无法判断目标语言，创建通用规则
            rule = Rule(
                id=rule_json['id'],
                name=rule_json['name'],
                description=rule_json['description'],
                pattern=rule_json['pattern'],
                severity=rule_json['severity'],
                category=rule_json['category']
            )
            # 添加规则并持久化到通用规则文件
            self.rules.append(rule)
            file_path = os.path.join(self.rules_dir, 'common_rules.json')
            self._save_rule_to_file(rule, file_path)
            
        return rule
                
    except ImportError:
        print("AI分析器未找到，无法转换规则")
        return None
    except Exception as e:
        print(f"转换规则时出错: {e}")
        return None

def __init__(self, rules_dir: str = 'rules'):
    self.rules = []
    # 加载各语言的规则
    rule_files = {
        'go': os.path.join(rules_dir, 'go_rules.json'),
        'rust': os.path.join(rules_dir, 'rust_rules.json'),
        'sol': os.path.join(rules_dir, 'sol_rules.json')
    }
    
    for file_path in rule_files.values():
        self.rules.extend(self._load_rules_from_json(file_path))
    
    self.parsers = {
        'go': go_ast.parse,
        'rust': rust_parser.parse,
        'sol': solidity_parser.parse
    }
