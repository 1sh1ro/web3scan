# Web3智能合约漏洞扫描系统

一个基于AI的智能合约安全分析工具，集成了多种扫描规则和GPT模型分析能力，帮助开发者快速发现和修复智能合约中的潜在安全漏洞。

## 🌟 核心特性

- **多语言支持**：支持扫描Solidity、Go、Rust等多种智能合约语言
- **AI辅助分析**：集成GPT-4模型，提供专业的漏洞分析和修复建议
- **自定义规则**：支持添加和管理自定义的扫描规则
- **批量处理**：支持ZIP压缩包批量上传和扫描
- **实时反馈**：即时展示扫描结果和安全建议

## 🛠️ 技术栈

- **后端**：Python + Flask
- **前端**：Vue.js + Element UI
- **AI模型**：OpenAI GPT-4
- **数据存储**：SQLite

## 📦 安装使用

1. 克隆项目
```bash
git clone [your-repository-url]
cd go-scan
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

3. 启动服务
```bash
python app.py
```
4. 配置环境
- 配置AI API密钥以及URL
- 确保uploads和results目录有写入权限

5. 访问系统
- 打开浏览器访问 http://localhost:5000

## 🔍 主要功能

### 合约扫描
- 支持单文件和批量上传
- 自动检测常见安全漏洞
- 提供详细的扫描报告

### AI分析
- 深度分析代码逻辑
- 提供专业的安全建议
- 生成修复方案

### 规则管理
- 内置多种安全规则
- 支持自定义规则
- 灵活的规则配置

## 📄 许可证

[MIT License](LICENSE)

## 🤝 贡献

欢迎提交Issue和Pull Request！

## 📞 联系方式

如有问题或建议，请通过以下方式联系：
- 提交Issue
- 发送邮件至：[yangxinmeng@tju.edu.cn]

## 🙏 致谢

感谢所有为本项目做出贡献的开发者！