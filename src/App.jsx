import React, { useState, useMemo } from 'react';
import { Shield, AlertTriangle, CheckCircle, Search, Copy, Terminal, Server, FileJson, Info } from 'lucide-react';

// --- Data & Logic Source: Based on the provided PDF "评分表（aggregate by qjj.pdf" ---

// 1. Docker Default Capabilities (Baseline - No Deduction)
const DOCKER_DEFAULT_CAPS = new Set([
  "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID",
  "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
  "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_SYS_CHROOT",
  "CAP_MKNOD", "CAP_AUDIT_WRITE", "CAP_SETFCAP"
]);

// 2. Risk Metadata (Intrinsic Level & Deduction)
const RISK_META = {
  // Critical (-30)
  "CAP_SYS_ADMIN": { level: "critical", deduct: 30, desc: "New Root, 挂载/命名空间/设备管理 (CVE-2022-0185)" },
  "CAP_SYS_MODULE": { level: "critical", deduct: 30, desc: "加载内核模块 (Rootkit注入)" },
  "CAP_SYS_RAWIO": { level: "critical", deduct: 30, desc: "原始I/O访问, 读写内核内存 (CVE-2022-0494)" },
  "CAP_SYS_PTRACE": { level: "critical", deduct: 30, desc: "进程调试/注入, 容器逃逸常见手段" },
  "CAP_NET_ADMIN": { level: "critical", deduct: 30, desc: "网络配置/防火墙管理 (CVE-2023-32233)" },
  "CAP_BPF": { level: "critical", deduct: 30, desc: "加载BPF程序, 内核代码执行" },
  "CAP_PERFMON": { level: "critical", deduct: 30, desc: "性能监控, 绕过观测范围限制" },
  "CAP_SYSLOG": { level: "critical", deduct: 30, desc: "读取内核日志/地址, 绕过KASLR" },

  // High (-20)
  "CAP_SYS_BOOT": { level: "high", deduct: 20, desc: "允许重启系统 (DoS攻击)" },
  "CAP_SYS_TIME": { level: "high", deduct: 20, desc: "修改系统时间, 影响日志/证书验证" },
  "CAP_SYS_RESOURCE": { level: "high", deduct: 20, desc: "修改资源限制 (ucheck/ulimit)" },
  "CAP_CHECKPOINT_RESTORE": { level: "high", deduct: 20, desc: "CRIU 检查点恢复, 控制PID" },
  "CAP_IPC_OWNER": { level: "high", deduct: 20, desc: "绕过IPC所有权检查" },
  "CAP_DAC_READ_SEARCH": { level: "high", deduct: 20, desc: "绕过文件读/目录搜索权限" },
  "CAP_MAC_ADMIN": { level: "high", deduct: 20, desc: "MAC配置/策略管理 (SELinux/AppArmor)" },
  "CAP_MAC_OVERRIDE": { level: "high", deduct: 20, desc: "覆盖MAC策略" },
  
  // High Intrinsic but Docker Default (Deduction will be 0 in logic)
  "CAP_SETUID": { level: "high", deduct: 20, desc: "修改进程UID (Docker默认)" },
  "CAP_SETGID": { level: "high", deduct: 20, desc: "修改进程GID (Docker默认)" },
  "CAP_SETPCAP": { level: "high", deduct: 20, desc: "修改进程Capabilities (Docker默认)" },
  "CAP_SETFCAP": { level: "high", deduct: 20, desc: "设置文件Capabilities (Docker默认)" },
  "CAP_DAC_OVERRIDE": { level: "high", deduct: 20, desc: "绕过DAC读写检查 (Docker默认)" },
  "CAP_NET_RAW": { level: "high", deduct: 20, desc: "使用原始套接字 (Docker默认)" },

  // Medium (-10)
  "CAP_AUDIT_CONTROL": { level: "medium", deduct: 10, desc: "控制内核审计系统" },
  "CAP_AUDIT_READ": { level: "medium", deduct: 10, desc: "读取审计日志" },
  "CAP_IPC_LOCK": { level: "medium", deduct: 10, desc: "锁定内存 (拒绝服务风险)" },
  "CAP_LINUX_IMMUTABLE": { level: "medium", deduct: 10, desc: "设置文件不可修改位 (隐藏恶意文件)" },
  "CAP_SYS_NICE": { level: "medium", deduct: 10, desc: "修改进程优先级 (资源抢占)" },
  "CAP_SYS_PACCT": { level: "medium", deduct: 10, desc: "进程记账管理" },
  "CAP_SYS_TTY_CONFIG": { level: "medium", deduct: 10, desc: "TTY配置 (键盘注入风险)" },
  "CAP_NET_BROADCAST": { level: "medium", deduct: 10, desc: "网络广播" },
  
  // Medium but Docker Default (Deduction 0)
  "CAP_MKNOD": { level: "medium", deduct: 10, desc: "创建特殊文件 (Docker默认)" },
  "CAP_SYS_CHROOT": { level: "medium", deduct: 10, desc: "使用chroot (Docker默认)" },
  "CAP_CHOWN": { level: "medium", deduct: 10, desc: "修改文件所有者 (Docker默认)" },
  "CAP_FOWNER": { level: "medium", deduct: 10, desc: "忽略文件所有权检查 (Docker默认)" },
  "CAP_FSETID": { level: "medium", deduct: 10, desc: "修改文件时保留SUID/SGID (Docker默认)" },
  "CAP_KILL": { level: "medium", deduct: 10, desc: "发送信号 (Docker默认)" },
  "CAP_AUDIT_WRITE": { level: "medium", deduct: 10, desc: "写入审计日志 (Docker默认)" },
  "CAP_NET_BIND_SERVICE": { level: "medium", deduct: 10, desc: "绑定<1024端口 (Docker默认)" },

  // Low (-5)
  "CAP_BLOCK_SUSPEND": { level: "low", deduct: 5, desc: "阻止系统休眠" },
  "CAP_WAKE_ALARM": { level: "low", deduct: 5, desc: "触发唤醒警报" },
  "CAP_LEASE": { level: "low", deduct: 5, desc: "文件租约" }
};

const ALL_CAPS_LIST = Object.keys(RISK_META).sort().map(name => ({
  name,
  ...RISK_META[name],
  isDefault: DOCKER_DEFAULT_CAPS.has(name)
}));

export default function App() {
  const [imageName, setImageName] = useState('nginx:latest');
  // Default selection matching typical secure web server needs
  const [selectedCaps, setSelectedCaps] = useState(
    ALL_CAPS_LIST.filter(c => ['CAP_NET_BIND_SERVICE', 'CAP_SETUID', 'CAP_SETGID', 'CAP_CHOWN'].includes(c.name))
  );
  const [searchQuery, setSearchQuery] = useState('');
  const [outputFormat, setOutputFormat] = useState('docker'); // docker, k8s, compose

  // --- Logic ---

  const unselectedCaps = useMemo(() => {
    const selectedNames = new Set(selectedCaps.map(c => c.name));
    return ALL_CAPS_LIST.filter(c => !selectedNames.has(c.name))
      .filter(c => c.name.toLowerCase().includes(searchQuery.toLowerCase()));
  }, [selectedCaps, searchQuery]);

  // Scoring Logic (PDF Page 5)
  const { score, level, levelText, scoreColor, details } = useMemo(() => {
    let deduction = 0;
    const breakdown = [];

    selectedCaps.forEach(cap => {
      // Logic: If it's a Docker default cap, deduction is 0 regardless of intrinsic risk
      const points = cap.isDefault ? 0 : cap.deduct;
      deduction += points;
      breakdown.push({ ...cap, actualDeduction: points });
    });

    const finalScore = Math.max(0, 100 - deduction);

    let l = "low";
    let lt = "极高风险";
    let color = "text-red-600";
    let barColor = "bg-red-500";

    if (finalScore >= 90) { l = "safe"; lt = "低风险"; color = "text-blue-600"; barColor = "bg-blue-600"; }
    else if (finalScore >= 75) { l = "medium"; lt = "中等风险"; color = "text-yellow-600"; barColor = "bg-yellow-500"; }
    else if (finalScore >= 50) { l = "high"; lt = "高风险"; color = "text-orange-600"; barColor = "bg-orange-500"; }

    return { score: finalScore, level: l, levelText: lt, scoreColor: color, barColor, details: breakdown };
  }, [selectedCaps]);

  // Code Generation
  const generatedCode = useMemo(() => {
    const capsToAdd = selectedCaps.map(c => c.name);
    // Remove "CAP_" prefix for K8s/Compose usually, but Docker CLI accepts both. 
    // We will keep CAP_ prefix for Docker CLI, remove for YAMLs to be standard compliant.
    const cleanCaps = capsToAdd.map(c => c.replace('CAP_', ''));

    if (outputFormat === 'docker') {
      let cmd = `docker run -d \\\n  --name ${imageName.split(':')[0]}-app \\\n  --cap-drop=ALL \\\n`;
      capsToAdd.forEach((cap, idx) => {
        cmd += `  --cap-add=${cap}${idx === capsToAdd.length - 1 ? '' : ' \\'}\n`;
      });
      cmd += `  ${imageName}`;
      return cmd;
    } 
    
    if (outputFormat === 'k8s') {
      return `apiVersion: v1
kind: Pod
metadata:
  name: ${imageName.split(':')[0]}-pod
spec:
  containers:
  - name: app
    image: ${imageName}
    securityContext:
      capabilities:
        drop:
          - ALL
        add:
${cleanCaps.map(c => `          - ${c}`).join('\n')}`;
    }

    if (outputFormat === 'compose') {
      return `version: "3.8"
services:
  app:
    image: ${imageName}
    cap_drop:
      - ALL
    cap_add:
${cleanCaps.map(c => `      - ${c}`).join('\n')}`;
    }
  }, [selectedCaps, imageName, outputFormat]);

  // --- Handlers ---

  const addCap = (cap) => {
    setSelectedCaps(prev => [...prev, cap].sort((a, b) => a.name.localeCompare(b.name)));
  };

  const removeCap = (cap) => {
    setSelectedCaps(prev => prev.filter(c => c.name !== cap.name));
  };

  const addAllDefaults = () => {
    const defaults = ALL_CAPS_LIST.filter(c => c.isDefault);
    const currentNames = new Set(selectedCaps.map(c => c.name));
    const toAdd = defaults.filter(d => !currentNames.has(d.name));
    setSelectedCaps(prev => [...prev, ...toAdd].sort((a, b) => a.name.localeCompare(b.name)));
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(generatedCode);
    // In a real app we'd show a toast here
  };

  // Helper for risk badge
  const RiskBadge = ({ level }) => {
    const colors = {
      critical: "bg-red-100 text-red-800 border-red-200",
      high: "bg-orange-100 text-orange-800 border-orange-200",
      medium: "bg-yellow-100 text-yellow-800 border-yellow-200",
      low: "bg-green-100 text-green-800 border-green-200",
    };
    return (
      <span className={`text-[10px] px-1.5 py-0.5 rounded border uppercase font-bold tracking-wider ${colors[level] || colors.low}`}>
        {level}
      </span>
    );
  };

  return (
    <div className="min-h-screen bg-slate-50 font-sans text-slate-800 p-4 md:p-8">
      
      {/* Header */}
      <div className="max-w-7xl mx-auto mb-8 text-center">
        <div className="inline-flex items-center justify-center p-3 bg-white rounded-full shadow-sm mb-4">
          <Shield className="w-8 h-8 text-blue-600 mr-2" />
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Linux Capabilities 评分配置器</h1>
        </div>
        <p className="text-slate-500 text-sm md:text-base max-w-2xl mx-auto">
          基于最小权限原则的容器安全配置工具。逻辑参考《容器安全评分表》，支持自动生成 Docker/K8s 配置。
        </p>
      </div>

      <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column: Input (3 cols) */}
        <div className="lg:col-span-3 space-y-6">
          <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide mb-4 flex items-center">
              <Server className="w-4 h-4 mr-2" /> 目标镜像
            </h2>
            <div className="relative">
              <input 
                type="text"
                value={imageName}
                onChange={(e) => setImageName(e.target.value)}
                className="w-full pl-3 pr-10 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all text-sm"
                placeholder="例如: nginx:alpine"
              />
              <div className="absolute right-3 top-2.5 text-slate-400">
                <Search className="w-4 h-4" />
              </div>
            </div>
            <div className="mt-3 text-xs text-slate-500 bg-slate-50 p-3 rounded border border-slate-100">
              <span className="font-semibold block mb-1">💡 提示:</span>
              Web服务器通常只需要 <code>NET_BIND_SERVICE</code>。只有需要特权的系统工具才需要 <code>SYS_ADMIN</code>。
            </div>
          </div>

          {/* Quick Stats */}
           <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-5">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide mb-4">当前统计</h2>
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-slate-500">已选能力</span>
                <span className="font-mono font-bold">{selectedCaps.length}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-slate-500">高危(Critical)</span>
                <span className={`font-mono font-bold ${details.some(d => d.level === 'critical') ? 'text-red-600' : 'text-slate-800'}`}>
                  {details.filter(d => d.level === 'critical').length}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-slate-500">扣分项</span>
                <span className="font-mono font-bold text-slate-800">
                  {details.filter(d => d.actualDeduction > 0).length}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Middle Column: Selection (5 cols) */}
        <div className="lg:col-span-5 flex flex-col h-[800px] lg:h-auto bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <div className="p-5 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
              配置 Capabilities
            </h2>
            <button 
              onClick={addAllDefaults}
              className="text-xs font-medium text-blue-600 hover:text-blue-700 hover:bg-blue-50 px-2 py-1 rounded transition-colors"
            >
              + 恢复 Docker 默认集
            </button>
          </div>

          {/* Search Bar */}
          <div className="px-5 py-3 border-b border-slate-100">
             <div className="relative">
              <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-400" />
              <input 
                type="text"
                placeholder="搜索 Capability (如: NET_ADMIN)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          {/* Selected List (Top area) */}
          <div className="border-b border-slate-200 flex flex-col bg-white">
            <div className="px-5 py-3 bg-slate-50 border-b border-slate-100 flex justify-between items-center">
               <span className="text-xs font-bold text-slate-500 uppercase">已选 ({selectedCaps.length})</span>
               <span className="text-[10px] text-slate-400">点击移除</span>
            </div>
            <div className="overflow-y-auto p-4 content-start">
              <div className="flex flex-wrap gap-2">
                {selectedCaps.map(cap => (
                  <button
                    key={cap.name}
                    onClick={() => removeCap(cap)}
                    className={`
                      group relative pl-2 pr-7 py-1 rounded text-xs font-mono font-medium border transition-all
                      ${cap.level === 'critical' ? 'bg-red-50 text-red-700 border-red-200 hover:bg-red-100' : 
                        cap.level === 'high' ? 'bg-orange-50 text-orange-700 border-orange-200 hover:bg-orange-100' :
                        'bg-blue-50 text-blue-700 border-blue-200 hover:bg-blue-100'}
                    `}
                  >
                    {cap.name}
                    <span className="absolute right-1.5 top-1 opacity-40 group-hover:opacity-100">×</span>
                  </button>
                ))}
                {selectedCaps.length === 0 && (
                  <div className="w-full text-center py-4 text-xs text-orange-400 bg-orange-50 rounded border border-orange-100 border-dashed">
                    ⚠️ 未选择任何 Capability，容器可能无法启动
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Available List */}
          <div className="flex-1 overflow-y-auto p-2 space-y-1 bg-slate-50/30">
            <div className="px-3 py-2 text-xs font-bold text-slate-400 uppercase">可用列表 ({unselectedCaps.length})</div>
            {unselectedCaps.map(cap => (
              <div 
                key={cap.name}
                onClick={() => addCap(cap)}
                className="group flex items-start p-3 mx-2 bg-white border border-slate-100 rounded-lg hover:border-blue-400 hover:shadow-md cursor-pointer transition-all duration-200"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center mb-1">
                    <span className="text-sm font-bold text-slate-700 mr-2 group-hover:text-blue-600 transition-colors">
                      {cap.name}
                    </span>
                    <RiskBadge level={cap.level} />
                    {cap.isDefault && <span className="ml-1 text-[10px] bg-slate-100 text-slate-500 px-1 rounded border">默认</span>}
                  </div>
                  <p className="text-xs text-slate-500 line-clamp-1">{cap.desc}</p>
                </div>
                <div className="text-slate-300 group-hover:text-blue-500">
                  <CheckCircle className="w-5 h-5" />
                </div>
              </div>
            ))}
            {unselectedCaps.length === 0 && (
              <div className="text-center py-10 text-slate-400 text-sm">没有匹配的能力项</div>
            )}
          </div>
        </div>

        {/* Right Column: Results (4 cols) */}
        <div className="lg:col-span-4 space-y-6">
          
          {/* Score Card */}
          <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-6 relative overflow-hidden">
            <div className="flex justify-between items-end mb-4 relative z-10">
              <div>
                <h2 className="text-sm font-bold text-slate-500 uppercase tracking-wide">安全评分</h2>
                <div className={`text-3xl font-extrabold mt-1 ${scoreColor}`}>
                  {levelText}
                </div>
              </div>
              <div className="text-right">
                <div className="text-xs text-slate-400 mb-1">总扣分</div>
                <div className="font-mono font-bold text-slate-700 text-lg">-{100 - score}</div>
              </div>
            </div>
            
            {/* Progress Bar */}
            <div className="w-full bg-slate-100 rounded-full h-3 mb-4 overflow-hidden relative z-10">
              <div 
                className={`h-full rounded-full transition-all duration-700 ease-out ${score.barColor}`}
                style={{ width: `${score}%`, backgroundColor: score >= 90 ? '#2563eb' : score >= 75 ? '#ca8a04' : '#dc2626' }}
              ></div>
            </div>

            {/* Critical Warning */}
            {details.some(d => d.level === 'critical') && (
               <div className="mt-4 bg-red-50 border border-red-100 rounded-lg p-3 flex items-start gap-3 relative z-10">
                 <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                 <div>
                   <h4 className="text-xs font-bold text-red-700 uppercase mb-1">检测到关键风险</h4>
                   <ul className="text-[11px] text-red-600 space-y-1 list-disc pl-3">
                     {details.filter(d => d.level === 'critical').slice(0, 3).map(d => (
                       <li key={d.name}>{d.name}: {d.desc}</li>
                     ))}
                   </ul>
                 </div>
               </div>
            )}
            
            {/* Background decoration */}
            <div className={`absolute -top-10 -right-10 w-32 h-32 rounded-full opacity-10 ${score >= 90 ? 'bg-blue-500' : 'bg-red-500'}`}></div>
          </div>

          {/* Code Output */}
          <div className="bg-slate-900 rounded-xl shadow-lg overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-4 py-3 bg-slate-800 border-b border-slate-700">
              <div className="flex space-x-1">
                <button 
                  onClick={() => setOutputFormat('docker')}
                  className={`px-3 py-1 rounded text-[10px] font-bold uppercase transition-colors ${outputFormat === 'docker' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'}`}
                >
                  <Terminal className="w-3 h-3 inline mr-1" /> Docker
                </button>
                <button 
                  onClick={() => setOutputFormat('compose')}
                  className={`px-3 py-1 rounded text-[10px] font-bold uppercase transition-colors ${outputFormat === 'compose' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'}`}
                >
                  <FileJson className="w-3 h-3 inline mr-1" /> Compose
                </button>
                <button 
                  onClick={() => setOutputFormat('k8s')}
                  className={`px-3 py-1 rounded text-[10px] font-bold uppercase transition-colors ${outputFormat === 'k8s' ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'}`}
                >
                  <Server className="w-3 h-3 inline mr-1" /> K8s
                </button>
              </div>
              <button onClick={copyToClipboard} className="text-slate-400 hover:text-white transition-colors" title="Copy">
                <Copy className="w-4 h-4" />
              </button>
            </div>
            
            <div className="p-4 overflow-x-auto relative group">
              <pre className="font-mono text-xs leading-relaxed text-green-400 whitespace-pre-wrap">
                {generatedCode}
              </pre>
            </div>
          </div>
          
          <div className="bg-blue-50 rounded-lg p-4 border border-blue-100 flex gap-3">
             <Info className="w-5 h-5 text-blue-600 flex-shrink-0" />
             <div className="text-xs text-blue-800">
               <p className="font-bold mb-1">最佳实践：Drop ALL First</p>
               <p>所有生成的配置均遵循 "Deny by Default" 原则，即先丢弃所有权限 (<code>drop: ALL</code>)，再按需添加白名单。</p>
             </div>
          </div>

        </div>
      </div>
    </div>
  );
}