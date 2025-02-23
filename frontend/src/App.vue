<template>
  <div id="app">
    <el-container>
      <el-header>
        <h1>Web3智能合约漏洞扫描器</h1>
      </el-header>
      
      <el-main>
        <el-row :gutter="20">
          <el-col :span="12">
            <el-card>
              <div slot="header">
                <span>合约扫描</span>
              </div>
              <el-upload
                class="upload-demo"
                drag
                action="/api/scan"
                :on-success="handleSuccess"
                :on-error="handleError">
                <i class="el-icon-upload"></i>
                <div class="el-upload__text">将文件拖到此处，或<em>点击上传</em></div>
              </el-upload>
              
              <el-form :model="scanForm" label-width="100px" class="scan-form">
                <el-form-item label="OpenAI Key">
                  <el-input v-model="scanForm.apiKey" placeholder="请输入OpenAI API密钥"></el-input>
                </el-form-item>
                <el-form-item label="扫描规则">
                  <el-select v-model="scanForm.selectedRules" multiple placeholder="选择扫描规则">
                    <el-option
                      v-for="rule in rules"
                      :key="rule.id"
                      :label="rule.name"
                      :value="rule.id">
                    </el-option>
                  </el-select>
                </el-form-item>
                <el-form-item>
                  <el-button type="primary" @click="startScan">开始扫描</el-button>
                </el-form-item>
              </el-form>
            </el-card>
          </el-col>
          
          <el-col :span="12">
            <el-card>
              <div slot="header">
                <span>扫描结果</span>
              </div>
              <el-table
                v-loading="loading"
                :data="scanResults"
                style="width: 100%">
                <el-table-column
                  prop="rule_id"
                  label="规则ID"
                  width="180">
                </el-table-column>
                <el-table-column
                  prop="severity"
                  label="严重程度"
                  width="100">
                  <template slot-scope="scope">
                    <el-tag :type="getSeverityType(scope.row.severity)">
                      {{ scope.row.severity }}
                    </el-tag>
                  </template>
                </el-table-column>
                <el-table-column
                  prop="explanation"
                  label="分析结果">
                </el-table-column>
                <el-table-column
                  fixed="right"
                  label="操作"
                  width="100">
                  <template slot-scope="scope">
                    <el-button @click="viewDetail(scope.row)" type="text" size="small">查看详情</el-button>
                  </template>
                </el-table-column>
              </el-table>
            </el-card>
          </el-col>
        </el-row>
        
        <!-- 详情对话框 -->
        <el-dialog
          title="漏洞详情"
          :visible.sync="dialogVisible"
          width="50%">
          <div v-if="currentVulnerability">
            <h3>漏洞描述</h3>
            <p>{{ currentVulnerability.explanation }}</p>
            
            <h3>POC</h3>
            <pre><code>{{ currentVulnerability.poc }}</code></pre>
            
            <h3>修复建议</h3>
            <p>{{ currentVulnerability.remediation }}</p>
          </div>
        </el-dialog>
      </el-main>
    </el-container>
  </div>
</template>

<script>
export default {
  name: 'App',
  data() {
    return {
      scanForm: {
        apiKey: '',
        selectedRules: []
      },
      rules: [],
      scanResults: [],
      loading: false,
      dialogVisible: false,
      currentVulnerability: null
    }
  },
  methods: {
    async loadRules() {
      try {
        const response = await fetch('/api/rules')
        this.rules = await response.json()
      } catch (error) {
        this.$message.error('加载规则失败')
      }
    },
    async startScan() {
      if (!this.scanForm.apiKey) {
        this.$message.warning('请输入OpenAI API密钥')
        return
      }
      this.loading = true
      // TODO: 实现扫描逻辑
    },
    handleSuccess(response) {
      this.$message.success('文件上传成功')
    },
    handleError() {
      this.$message.error('文件上传失败')
    },
    getSeverityType(severity) {
      const types = {
        high: 'danger',
        medium: 'warning',
        low: 'info'
      }
      return types[severity.toLowerCase()] || 'info'
    },
    viewDetail(vulnerability) {
      this.currentVulnerability = vulnerability
      this.dialogVisible = true
    }
  },
  created() {
    this.loadRules()
  }
}
</script>

<style>
#app {
  font-family: 'Helvetica Neue', Helvetica, 'PingFang SC', 'Hiragino Sans GB',
    'Microsoft YaHei', '微软雅黑', Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: #2c3e50;
}

.el-header {
  background-color: #409EFF;
  color: white;
  line-height: 60px;
  text-align: center;
}

.el-main {
  padding: 20px;
  background-color: #f0f2f5;
}

.scan-form {
  margin-top: 20px;
}

.el-card {
  margin-bottom: 20px;
}

pre {
  background-color: #f5f7fa;
  padding: 15px;
  border-radius: 4px;
  overflow-x: auto;
}
</style>