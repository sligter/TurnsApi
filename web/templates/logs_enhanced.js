// 增强的日志管理JavaScript代码
// Chart.js 全局配置
Chart.defaults.font.family = 'system-ui, -apple-system, sans-serif';
Chart.defaults.color = '#374151';
Chart.defaults.borderColor = '#E5E7EB';
Chart.defaults.backgroundColor = 'rgba(59, 130, 246, 0.1)';

// 注册插件
Chart.register(ChartDataLabels);

// 现代化颜色方案
const CHART_COLORS = {
    primary: '#3B82F6',
    secondary: '#10B981',
    accent: '#F59E0B',
    danger: '#EF4444',
    purple: '#8B5CF6',
    pink: '#EC4899',
    cyan: '#06B6D4',
    lime: '#84CC16',
    gray: '#6B7280'
};

// 图表工具类
class ChartManager {
    constructor() {
        this.charts = {};
        this.defaultOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        usePointStyle: true,
                        padding: 20,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#fff',
                    bodyColor: '#fff',
                    borderColor: '#374151',
                    borderWidth: 1,
                    cornerRadius: 8,
                    displayColors: true,
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.parsed !== null) {
                                label += new Intl.NumberFormat('zh-CN').format(context.parsed);
                            }
                            return label;
                        }
                    }
                }
            },
            animation: {
                duration: 1000,
                easing: 'easeInOutQuart'
            }
        };
    }

    createPieChart(canvasId, data, options = {}) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        const config = {
            type: 'doughnut',
            data: data,
            options: {
                ...this.defaultOptions,
                ...options,
                plugins: {
                    ...this.defaultOptions.plugins,
                    ...options.plugins,
                    datalabels: {
                        color: '#fff',
                        font: {
                            weight: 'bold',
                            size: 14
                        },
                        formatter: (value, context) => {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return percentage + '%';
                        }
                    }
                },
                cutout: '50%'
            }
        };

        if (this.charts[canvasId]) {
            this.charts[canvasId].destroy();
        }

        this.charts[canvasId] = new Chart(ctx, config);
        return this.charts[canvasId];
    }

    createBarChart(canvasId, data, options = {}) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        const config = {
            type: 'bar',
            data: data,
            options: {
                ...this.defaultOptions,
                ...options,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)',
                            drawBorder: false
                        },
                        ticks: {
                            font: {
                                size: 11
                            }
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            font: {
                                size: 11
                            },
                            maxRotation: 45
                        }
                    }
                },
                plugins: {
                    ...this.defaultOptions.plugins,
                    ...options.plugins,
                    datalabels: {
                        anchor: 'end',
                        align: 'top',
                        color: '#374151',
                        font: {
                            size: 10,
                            weight: 'bold'
                        },
                        formatter: (value) => {
                            return new Intl.NumberFormat('zh-CN').format(value);
                        }
                    }
                }
            }
        };

        if (this.charts[canvasId]) {
            this.charts[canvasId].destroy();
        }

        this.charts[canvasId] = new Chart(ctx, config);
        return this.charts[canvasId];
    }

    createLineChart(canvasId, data, options = {}) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        const config = {
            type: 'line',
            data: data,
            options: {
                ...this.defaultOptions,
                ...options,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.1)',
                            drawBorder: false
                        },
                        ticks: {
                            font: {
                                size: 11
                            },
                            callback: function(value) {
                                return new Intl.NumberFormat('zh-CN').format(value);
                            }
                        }
                    },
                    x: {
                        type: 'time',
                        time: {
                            displayFormats: {
                                hour: 'HH:mm',
                                day: 'MM/dd'
                            }
                        },
                        grid: {
                            display: false
                        },
                        ticks: {
                            font: {
                                size: 11
                            }
                        }
                    }
                },
                plugins: {
                    ...this.defaultOptions.plugins,
                    ...options.plugins,
                    zoom: {
                        zoom: {
                            wheel: {
                                enabled: true,
                            },
                            pinch: {
                                enabled: true
                            },
                            mode: 'x',
                        },
                        pan: {
                            enabled: true,
                            mode: 'x',
                        }
                    }
                },
                elements: {
                    line: {
                        tension: 0.4,
                        borderWidth: 3
                    },
                    point: {
                        radius: 4,
                        hoverRadius: 6,
                        borderWidth: 2
                    }
                }
            }
        };

        if (this.charts[canvasId]) {
            this.charts[canvasId].destroy();
        }

        this.charts[canvasId] = new Chart(ctx, config);
        return this.charts[canvasId];
    }

    destroyChart(canvasId) {
        if (this.charts[canvasId]) {
            this.charts[canvasId].destroy();
            delete this.charts[canvasId];
        }
    }

    resetZoom(canvasId) {
        if (this.charts[canvasId] && this.charts[canvasId].resetZoom) {
            this.charts[canvasId].resetZoom();
        }
    }

    exportChart(canvasId, filename = 'chart') {
        if (this.charts[canvasId]) {
            const canvas = this.charts[canvasId].canvas;
            const url = canvas.toDataURL('image/png');
            const link = document.createElement('a');
            link.download = `${filename}.png`;
            link.href = url;
            link.click();
        }
    }
}

// 数据导出工具类
class DataExporter {
    static exportToCSV(data, filename = 'data') {
        if (!data || data.length === 0) return;

        const headers = Object.keys(data[0]);
        const csvContent = [
            headers.join(','),
            ...data.map(row => headers.map(header => {
                const value = row[header];
                return typeof value === 'string' && value.includes(',') ? `"${value}"` : value;
            }).join(','))
        ].join('\n');

        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `${filename}.csv`;
        link.click();
    }

    static async exportToPDF(elementId, filename = 'report') {
        const element = document.getElementById(elementId);
        if (!element) return;

        try {
            const canvas = await html2canvas(element, {
                scale: 2,
                useCORS: true,
                allowTaint: true
            });

            const imgData = canvas.toDataURL('image/png');
            const pdf = new jsPDF('p', 'mm', 'a4');
            const imgWidth = 210;
            const pageHeight = 295;
            const imgHeight = (canvas.height * imgWidth) / canvas.width;
            let heightLeft = imgHeight;

            let position = 0;

            pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
            heightLeft -= pageHeight;

            while (heightLeft >= 0) {
                position = heightLeft - imgHeight;
                pdf.addPage();
                pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
                heightLeft -= pageHeight;
            }

            pdf.save(`${filename}.pdf`);
        } catch (error) {
            console.error('PDF导出失败:', error);
            alert('PDF导出失败，请重试');
        }
    }
}

// 扩展日志管理功能
function enhancedLogsManagement() {
    const chartManager = new ChartManager();
    
    return {
        // 基础数据
        logs: [],
        logDetail: null,
        showDetailModal: false,
        showConfirmModal: false,
        confirmTitle: '',
        confirmMessage: '',
        confirmCallback: null,
        selectedLogs: [],
        currentPage: 1,
        pageSize: 20,
        totalCount: 0,
        
        // 统计数据
        totalRequests: 0,
        successRequests: 0,
        errorRequests: 0,
        avgResponseTime: 0,
        totalTokensUsed: 0,
        successTokensUsed: 0,
        avgTokensPerRequest: 0,
        tokenSuccessRate: 0,
        
        // 历史数据用于趋势计算
        previousStats: {
            totalTokensUsed: 0,
            successTokensUsed: 0,
            avgTokensPerRequest: 0,
            tokenSuccessRate: 0
        },
        
        // 筛选数据
        proxyKeys: [],
        providerGroups: [],
        models: [],
        filters: {
            proxyKeyName: '',
            providerGroup: '',
            model: '',
            status: '',
            stream: ''
        },
        
        // 图表相关
        charts: {},
        chartsLoading: {
            status: false,
            model: false,
            tokenTrend: false,
            responseTime: false,
            groupToken: false,
            heatmap: false
        },
        chartTimeRange: '24h',
        // 全局聚合图表数据（与分页数据解耦）
        chartData: {
            status: { success: 0, error: 0 },
            model: { labels: [], counts: [] },
            tokenTrend: { labels: [], total: [], success: [] },
            groupToken: { labels: [], total: [], success: [] }
        },
        
        // 实时更新
        autoRefresh: false,
        refreshInterval: null,
        nextUpdateCountdown: 30,
        countdownInterval: null,
        
        // 全屏显示
        fullscreenChart: false,
        fullscreenChartTitle: '',
        fullscreenChartContent: '',

        async init() {
            await Promise.all([
                this.loadLogs(),
                this.loadStats(),
                this.loadTokenStats(),
                this.loadChartData()
            ]);
            
            // 延迟初始化图表，确保数据已加载
            setTimeout(() => {
                this.initCharts();
            }, 100);
            
            // 监听窗口大小变化
            window.addEventListener('resize', this.handleResize.bind(this));
        },

        get totalPages() {
            return Math.ceil(this.totalCount / this.pageSize);
        },

        // 数据加载方法
        async loadLogs() {
            try {
                const params = new URLSearchParams({
                    limit: this.pageSize,
                    offset: (this.currentPage - 1) * this.pageSize
                });

                if (this.filters.proxyKeyName) params.append('proxy_key_name', this.filters.proxyKeyName);
                if (this.filters.providerGroup) params.append('provider_group', this.filters.providerGroup);
                if (this.filters.model) params.append('model', this.filters.model);
                if (this.filters.status) params.append('status', this.filters.status);
                if (this.filters.stream) params.append('stream', this.filters.stream);

                const response = await fetch(`/admin/logs?${params}`);
                const data = await response.json();

                if (data.success) {
                    this.logs = data.logs || [];
                    this.totalCount = data.total_count || 0;
                    this.selectedLogs = []; // 清空选中状态
                    this.extractFilters();
                } else {
                    console.error('Failed to load logs:', data.error);
                }
            } catch (error) {
                console.error('Error loading logs:', error);
            }
        },

        async loadStats() {
            try {
                const proxyKeyStatsResponse = await fetch('/admin/logs/stats/api-keys');
                const proxyKeyStats = await proxyKeyStatsResponse.json();

                if (proxyKeyStats.success) {
                    const stats = proxyKeyStats.stats || [];
                    this.totalRequests = stats.reduce((sum, stat) => sum + stat.total_requests, 0);
                    this.successRequests = stats.reduce((sum, stat) => sum + stat.success_requests, 0);
                    this.errorRequests = stats.reduce((sum, stat) => sum + stat.error_requests, 0);
                    this.avgResponseTime = Math.round(stats.reduce((sum, stat) => sum + stat.avg_duration, 0) / stats.length) || 0;
                }
            } catch (error) {
                console.error('Error loading stats:', error);
            }
        },

        async loadTokenStats() {
            try {
                // 保存之前的统计数据用于趋势计算
                this.previousStats = {
                    totalTokensUsed: this.totalTokensUsed,
                    successTokensUsed: this.successTokensUsed,
                    avgTokensPerRequest: this.avgTokensPerRequest,
                    tokenSuccessRate: this.tokenSuccessRate
                };

                const response = await fetch('/admin/logs/stats/tokens');
                const data = await response.json();

                if (data.success && data.stats) {
                    this.totalTokensUsed = data.stats.total_tokens || 0;
                    this.successTokensUsed = data.stats.success_tokens || 0;
                    this.avgTokensPerRequest = data.stats.success_requests > 0 ?
                        Math.round(this.successTokensUsed / data.stats.success_requests) : 0;
                    this.tokenSuccessRate = data.stats.total_requests > 0 ?
                        Math.round((data.stats.success_requests / data.stats.total_requests) * 100) : 0;
                }
            } catch (error) {
                console.error('Error loading token stats:', error);
            }
        },

        // 获取Token趋势
        getTokenTrend(type) {
            const current = this[type === 'total' ? 'totalTokensUsed' : 
                                 type === 'success' ? 'successTokensUsed' :
                                 type === 'avg' ? 'avgTokensPerRequest' : 'tokenSuccessRate'];
            const previous = this.previousStats[type === 'total' ? 'totalTokensUsed' : 
                                               type === 'success' ? 'successTokensUsed' :
                                               type === 'avg' ? 'avgTokensPerRequest' : 'tokenSuccessRate'];
            
            if (previous === 0) return '';
            
            const change = current - previous;
            const percentage = Math.abs(Math.round((change / previous) * 100));
            
            if (change > 0) {
                return `↗ +${percentage}%`;
            } else if (change < 0) {
                return `↘ -${percentage}%`;
            } else {
                return '→ 0%';
            }
        },

        extractFilters() {
            const proxyKeys = new Set();
            const providerGroups = new Set();
            const models = new Set();

            this.logs.forEach(log => {
                if (log.proxy_key_name) {
                    proxyKeys.add(log.proxy_key_name);
                }
                if (log.provider_group) {
                    providerGroups.add(log.provider_group);
                }
                if (log.model) {
                    models.add(log.model);
                }
            });

            this.proxyKeys = Array.from(proxyKeys).sort();
            this.providerGroups = Array.from(providerGroups).sort();
            this.models = Array.from(models).sort();
        },

        applyFilters() {
            this.currentPage = 1;
            this.loadLogs();
        },

        // 加载全量聚合图表数据（后端端点占位，若缺失则降级为现有stats或前端聚合）
        async loadChartData() {
            try {
                // 组装查询参数（时间范围 + 过滤器）
                const params = new URLSearchParams({ range: this.chartTimeRange });
                if (this.filters.proxyKeyName) params.append('proxy_key_name', this.filters.proxyKeyName);
                if (this.filters.providerGroup) params.append('provider_group', this.filters.providerGroup);
                if (this.filters.model) params.append('model', this.filters.model);
                if (this.filters.status) params.append('status', this.filters.status);
                if (this.filters.stream) params.append('stream', this.filters.stream);

                // 并行请求后端聚合端点；若端点暂未实现，将尝试降级
                const fetchSafe = async (url) => {
                    try {
                        const res = await fetch(url);
                        if (!res.ok) return null;
                        const json = await res.json();
                        return json;
                    } catch (e) {
                        return null;
                    }
                };

                // 目前后端仅有 models 和 tokens 汇总，不含 status、timeline、group-tokens 专用端点
                const [statusRes, modelRes, tokenTrendRes, groupTokenRes] = await Promise.all([
                    fetchSafe(`/admin/logs/stats/status?${params}`),
                    fetchSafe(`/admin/logs/stats/models?${params}`),
                    fetchSafe(`/admin/logs/stats/tokens-timeline?${params}`),
                    fetchSafe(`/admin/logs/stats/group-tokens?${params}`)
                ]);

                // 状态分布：若无后端端点，则用现有 this.successRequests / this.errorRequests 兜底
                if (statusRes && statusRes.success) {
                    const s = statusRes.data || statusRes.stats || {};
                    this.chartData.status = {
                        success: Number(s.success || 0),
                        error: Number(s.error || 0)
                    };
                } else {
                    this.chartData.status = {
                        success: Number(this.successRequests || 0),
                        error: Number(this.errorRequests || 0)
                    };
                }

                // 模型统计：优先用后端返回（有全量统计），若失败则从分页数据临时聚合兜底
                if (modelRes && modelRes.success) {
                    const list = modelRes.data || modelRes.stats || [];
                    const top = list
                        .map(it => ({
                            label: it.model || it.label || 'unknown',
                            count: Number(it.total_requests ?? it.count ?? 0)
                        }))
                        .sort((a, b) => b.count - a.count)
                        .slice(0, 10);
                    this.chartData.model = {
                        labels: top.map(i => i.label),
                        counts: top.map(i => i.count)
                    };
                } else {
                    // 兜底：从当前分页 this.logs 粗略统计（不准确，但可用）
                    const modelStats = {};
                    this.logs.forEach(log => {
                        if (log.model) modelStats[log.model] = (modelStats[log.model] || 0) + 1;
                    });
                    const sorted = Object.entries(modelStats).sort((a, b) => b[1] - a[1]).slice(0, 10);
                    this.chartData.model = {
                        labels: sorted.map(([m]) => m),
                        counts: sorted.map(([, c]) => c)
                    };
                }

                // Token 时间线：若无端点，则空数据（或可基于分页数据粗略聚合）
                if (tokenTrendRes && tokenTrendRes.success) {
                    const series = tokenTrendRes.data || tokenTrendRes.stats || [];
                    const sorted = [...series].sort((a, b) => String(a.date).localeCompare(String(b.date)));
                    this.chartData.tokenTrend = {
                        labels: sorted.map(i => i.date),
                        total: sorted.map(i => Number(i.total || 0)),
                        success: sorted.map(i => Number(i.success || 0))
                    };
                } else {
                    // 兜底：用分页数据粗略汇总
                    const tokenByDate = {};
                    this.logs.forEach(log => {
                        if (log.tokens_used && log.tokens_used > 0 && log.created_at) {
                            const date = new Date(log.created_at).toISOString().split('T')[0];
                            tokenByDate[date] = (tokenByDate[date] || 0) + (log.tokens_used || 0);
                        }
                    });
                    const sorted = Object.entries(tokenByDate)
                        .map(([date, tokens]) => ({ date, total: tokens, success: 0 }))
                        .sort((a, b) => a.date.localeCompare(b.date));
                    this.chartData.tokenTrend = {
                        labels: sorted.map(i => i.date),
                        total: sorted.map(i => Number(i.total || 0)),
                        success: sorted.map(() => 0)
                    };
                }

                // 分组 Token 聚合：若无端点，则从分页数据粗略聚合
                if (groupTokenRes && groupTokenRes.success) {
                    const groups = groupTokenRes.data || groupTokenRes.stats || [];
                    this.chartData.groupToken = {
                        labels: groups.map(i => i.group || i.label || '-'),
                        total: groups.map(i => Number(i.total || 0)),
                        success: groups.map(i => Number(i.success || 0))
                    };
                } else {
                    const groupTokens = {};
                    this.logs.forEach(log => {
                        if (log.provider_group && log.tokens_used && log.tokens_used > 0) {
                            groupTokens[log.provider_group] = (groupTokens[log.provider_group] || 0) + (log.tokens_used || 0);
                        }
                    });
                    const sortedGroups = Object.entries(groupTokens).sort((a, b) => b[1] - a[1]).slice(0, 10);
                    this.chartData.groupToken = {
                        labels: sortedGroups.map(([g]) => g),
                        total: sortedGroups.map(([, t]) => Number(t || 0)),
                        success: sortedGroups.map(() => 0)
                    };
                }
            } catch (e) {
                console.error('Error loading chart aggregated data:', e);
            }
        },

        async viewLogDetail(id) {
            try {
                const response = await fetch(`/admin/logs/${id}`);
                const data = await response.json();

                if (data.success) {
                    this.logDetail = data.log;
                    this.showDetailModal = true;
                } else {
                    console.error('Failed to load log detail:', data.error);
                }
            } catch (error) {
                console.error('Error loading log detail:', error);
            }
        },

        async refreshLogs() {
            await Promise.all([
                this.loadLogs(),
                this.loadStats(),
                this.loadTokenStats(),
                this.loadChartData()
            ]);
            // 延迟更新图表，确保数据已加载
            setTimeout(() => {
                this.updateCharts();
            }, 100);
        },

        refreshTokenStats() {
            this.loadTokenStats();
        },

        // 实时更新功能
        toggleAutoRefresh() {
            this.autoRefresh = !this.autoRefresh;
            
            if (this.autoRefresh) {
                this.startAutoRefresh();
            } else {
                this.stopAutoRefresh();
            }
        },

        startAutoRefresh() {
            this.nextUpdateCountdown = 30;
            
            // 开始倒计时
            this.countdownInterval = setInterval(() => {
                this.nextUpdateCountdown--;
                if (this.nextUpdateCountdown <= 0) {
                    this.nextUpdateCountdown = 30;
                }
            }, 1000);
            
            // 开始自动刷新
            this.refreshInterval = setInterval(async () => {
                await this.refreshLogs();
            }, 30000);
        },

        stopAutoRefresh() {
            if (this.refreshInterval) {
                clearInterval(this.refreshInterval);
                this.refreshInterval = null;
            }
            if (this.countdownInterval) {
                clearInterval(this.countdownInterval);
                this.countdownInterval = null;
            }
        },

        previousPage() {
            if (this.currentPage > 1) {
                this.currentPage--;
                this.loadLogs();
            }
        },

        nextPage() {
            if (this.currentPage < this.totalPages) {
                this.currentPage++;
                this.loadLogs();
            }
        },

        formatDate(dateString) {
            if (!dateString) return '';
            const date = new Date(dateString);
            return date.toLocaleString('zh-CN');
        },

        formatJSON(jsonString) {
            if (!jsonString) return '';
            try {
                const obj = JSON.parse(jsonString);
                return JSON.stringify(obj, null, 2);
            } catch (e) {
                return jsonString;
            }
        },

        formatResponse(responseString) {
            if (!responseString) return '无响应内容';

            // 如果是流式响应，显示前几行
            if (responseString.includes('data: ')) {
                const lines = responseString.split('\n').slice(0, 10);
                return lines.join('\n') + (responseString.split('\n').length > 10 ? '\n...(更多内容)' : '');
            }

            // 尝试格式化JSON
            try {
                const obj = JSON.parse(responseString);
                return JSON.stringify(obj, null, 2);
            } catch (e) {
                return responseString;
            }
        },

        // 批量选择相关方法
        toggleLogSelection(logId) {
            const index = this.selectedLogs.indexOf(logId);
            if (index > -1) {
                this.selectedLogs.splice(index, 1);
            } else {
                this.selectedLogs.push(logId);
            }
        },

        toggleSelectAll() {
            if (this.isAllSelected()) {
                this.selectedLogs = [];
            } else {
                this.selectedLogs = this.logs.map(log => log.id);
            }
        },

        isAllSelected() {
            return this.logs.length > 0 && this.selectedLogs.length === this.logs.length;
        },

        // 删除选中的日志
        deleteSelectedLogs() {
            if (this.selectedLogs.length === 0) {
                alert('请先选择要删除的日志');
                return;
            }

            this.confirmTitle = '确认删除';
            this.confirmMessage = `确定要删除选中的 ${this.selectedLogs.length} 条日志吗？此操作不可撤销。`;
            this.confirmCallback = this.performDeleteSelected;
            this.showConfirmModal = true;
        },

        async performDeleteSelected() {
            try {
                // 确保ID是数字类型
                const ids = this.selectedLogs.map(id => parseInt(id, 10)).filter(id => !isNaN(id));

                if (ids.length === 0) {
                    alert('没有有效的日志ID可删除');
                    return;
                }



                const response = await fetch('/admin/logs/batch', {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        ids: ids
                    })
                });

                const data = await response.json();

                if (data.success) {
                    alert(`成功删除 ${data.deleted_count} 条日志`);
                    this.selectedLogs = [];
                    this.loadLogs();
                    this.loadStats();
                } else {
                    alert('删除失败: ' + data.error);
                }
            } catch (error) {
                console.error('Error deleting logs:', error);
                alert('删除失败: ' + error.message);
            }

            this.showConfirmModal = false;
        },

        // 清空错误日志
        clearErrorLogs() {
            this.confirmTitle = '确认清空错误日志';
            this.confirmMessage = '确定要清空所有错误日志吗？此操作将删除所有状态码不为200的日志记录，不可撤销。';
            this.confirmCallback = this.performClearErrors;
            this.showConfirmModal = true;
        },

        // 清空所有日志
        clearAllLogs() {
            this.confirmTitle = '确认清空';
            this.confirmMessage = '确定要清空所有日志吗？此操作将删除所有日志记录，不可撤销。';
            this.confirmCallback = this.performClearAll;
            this.showConfirmModal = true;
        },

        async performClearAll() {
            try {
                const response = await fetch('/admin/logs/clear', {
                    method: 'DELETE'
                });

                const data = await response.json();

                if (data.success) {
                    alert(`成功清空所有日志，删除了 ${data.deleted_count} 条记录`);
                    this.selectedLogs = [];
                    this.loadLogs();
                    this.loadStats();
                } else {
                    alert('清空失败: ' + data.error);
                }
            } catch (error) {
                console.error('Error clearing logs:', error);
                alert('清空失败: ' + error.message);
            }

            this.showConfirmModal = false;
        },

        async performClearErrors() {
            try {
                const response = await fetch('/admin/logs/clear-errors', {
                    method: 'DELETE'
                });

                const data = await response.json();

                if (data.success) {
                    alert(`成功清空错误日志，删除了 ${data.deleted_count} 条记录`);
                    this.selectedLogs = [];
                    this.loadLogs();
                    this.loadStats();
                } else {
                    alert('清空错误日志失败: ' + data.error);
                }
            } catch (error) {
                console.error('Error clearing error logs:', error);
                alert('清空错误日志失败: ' + error.message);
            }

            this.showConfirmModal = false;
        },

        // 导出日志
        async exportLogs() {
            try {
                const params = new URLSearchParams();
                if (this.filters.proxyKeyName) params.append('proxy_key_name', this.filters.proxyKeyName);
                if (this.filters.providerGroup) params.append('provider_group', this.filters.providerGroup);
                if (this.filters.model) params.append('model', this.filters.model);
                if (this.filters.status) params.append('status', this.filters.status);
                if (this.filters.stream) params.append('stream', this.filters.stream);
                params.append('format', 'csv');

                const url = `/admin/logs/export?${params}`;

                // 创建一个隐藏的链接来触发下载
                const link = document.createElement('a');
                link.href = url;
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            } catch (error) {
                console.error('Error exporting logs:', error);
                alert('导出失败: ' + error.message);
            }
        },

        // Token统计导出
        exportTokenStats() {
            const stats = [
                {
                    '指标': '总Token数',
                    '数值': this.totalTokensUsed,
                    '趋势': this.getTokenTrend('total')
                },
                {
                    '指标': '成功Token数',
                    '数值': this.successTokensUsed,
                    '趋势': this.getTokenTrend('success')
                },
                {
                    '指标': '平均Token/请求',
                    '数值': this.avgTokensPerRequest,
                    '趋势': this.getTokenTrend('avg')
                },
                {
                    '指标': 'Token成功率',
                    '数值': this.tokenSuccessRate + '%',
                    '趋势': this.getTokenTrend('rate')
                }
            ];

            DataExporter.exportToCSV(stats, 'token_stats');
        },

        // 确认操作
        confirmAction() {
            if (this.confirmCallback) {
                this.confirmCallback();
            }
        },

        // 图表相关方法
        initCharts() {
            this.createStatusChart();
            this.createModelChart();
            this.createTokenTrendChart();
            this.createGroupTokenChart();
        },

        updateCharts() {
            this.createStatusChart();
            this.createModelChart();
            this.createTokenTrendChart();
            this.createGroupTokenChart();
        },

        async updateChartsWithTimeRange() {
            // 根据时间范围更新图表数据（从后端聚合端点获取）
            await this.loadChartData();
            this.updateCharts();
        },

        resetAllCharts() {
            Object.keys(chartManager.charts).forEach(chartId => {
                chartManager.resetZoom(chartId);
            });
        },

        exportChart(chartId) {
            chartManager.exportChart(chartId, chartId);
        },

        async exportAllCharts() {
            try {
                await DataExporter.exportToPDF('charts-section', 'charts_report');
            } catch (error) {
                console.error('导出图表失败:', error);
                alert('导出图表失败，请重试');
            }
        },

        toggleFullscreen(chartId) {
            this.fullscreenChart = !this.fullscreenChart;
            this.fullscreenChartTitle = chartId;
            // 实现全屏显示逻辑
        },

        exitFullscreen() {
            this.fullscreenChart = false;
        },

        // 创建状态分布饼图（使用全局聚合数据）
        createStatusChart() {
            this.chartsLoading.status = true;

            const success = this.chartData?.status?.success ?? this.successRequests ?? 0;
            const error = this.chartData?.status?.error ?? this.errorRequests ?? 0;

            const data = {
                labels: ['成功请求', '失败请求'],
                datasets: [{
                    data: [success, error],
                    backgroundColor: [CHART_COLORS.secondary, CHART_COLORS.danger],
                    borderColor: ['#fff', '#fff'],
                    borderWidth: 2,
                    hoverOffset: 10
                }]
            };

            chartManager.createPieChart('statusChart', data, {
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = total > 0 ? Math.round((context.parsed / total) * 100) : 0;
                                return `${context.label}: ${context.parsed} (${percentage}%)`;
                            }
                        }
                    }
                }
            });

            this.chartsLoading.status = false;
        },

        // 创建模型使用统计柱状图（使用全局聚合数据）
        createModelChart() {
            this.chartsLoading.model = true;

            const labels = this.chartData?.model?.labels ?? [];
            const counts = this.chartData?.model?.counts ?? [];

            const displayLabels = labels.map(m => m && m.length > 15 ? m.substring(0, 15) + '...' : (m || '未知模型'));

            const data = {
                labels: displayLabels.slice(0, 8),
                datasets: [{
                    label: '使用次数',
                    data: counts.slice(0, 8),
                    backgroundColor: CHART_COLORS.primary,
                    borderColor: CHART_COLORS.primary,
                    borderWidth: 1,
                    borderRadius: 4,
                    borderSkipped: false,
                }]
            };

            chartManager.createBarChart('modelChart', data);
            this.chartsLoading.model = false;
        },

        // 创建Token使用趋势图（使用全局聚合数据）
        createTokenTrendChart() {
            this.chartsLoading.tokenTrend = true;

            const labels = this.chartData?.tokenTrend?.labels ?? [];
            const total = this.chartData?.tokenTrend?.total ?? [];
            const success = this.chartData?.tokenTrend?.success ?? [];

            // 构造时间序列点
            const seriesTotal = labels.map((d, i) => ({ x: new Date(d), y: total[i] || 0 }));
            const seriesSuccess = labels.map((d, i) => ({ x: new Date(d), y: success[i] || 0 }));

            const data = {
                datasets: [
                    {
                        label: 'Token总量',
                        data: seriesTotal,
                        borderColor: CHART_COLORS.purple,
                        backgroundColor: CHART_COLORS.purple + '20',
                        fill: true,
                        tension: 0.4,
                        pointBackgroundColor: CHART_COLORS.purple,
                        pointBorderColor: '#fff',
                        pointBorderWidth: 2,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    },
                    {
                        label: '成功Token',
                        data: seriesSuccess,
                        borderColor: CHART_COLORS.secondary,
                        backgroundColor: CHART_COLORS.secondary + '20',
                        fill: true,
                        tension: 0.4,
                        pointBackgroundColor: CHART_COLORS.secondary,
                        pointBorderColor: '#fff',
                        pointBorderWidth: 2,
                        pointRadius: 3,
                        pointHoverRadius: 5
                    }
                ]
            };

            chartManager.createLineChart('tokenTrendChart', data);
            this.chartsLoading.tokenTrend = false;
        },

        // 创建各分组Token数统计图（使用全局聚合数据）
        createGroupTokenChart() {
            this.chartsLoading.groupToken = true;

            const labels = this.chartData?.groupToken?.labels ?? [];
            const total = this.chartData?.groupToken?.total ?? [];
            const success = this.chartData?.groupToken?.success ?? [];

            const colors = [
                CHART_COLORS.primary, CHART_COLORS.secondary, CHART_COLORS.accent,
                CHART_COLORS.danger, CHART_COLORS.purple, CHART_COLORS.pink,
                CHART_COLORS.cyan, CHART_COLORS.lime
            ];

            const viewLabels = labels.map(g => g && g.length > 12 ? g.substring(0, 12) + '...' : (g || '-'));

            const data = {
                labels: viewLabels.slice(0, 8),
                datasets: [
                    {
                        label: 'Token总量',
                        data: total.slice(0, 8),
                        backgroundColor: colors.slice(0, Math.min(8, labels.length)),
                        borderColor: colors.slice(0, Math.min(8, labels.length)),
                        borderWidth: 1,
                        borderRadius: 4,
                        borderSkipped: false,
                    },
                    {
                        label: '成功Token',
                        data: success.slice(0, 8),
                        backgroundColor: CHART_COLORS.secondary + '55',
                        borderColor: CHART_COLORS.secondary,
                        borderWidth: 1,
                        borderRadius: 4,
                        borderSkipped: false,
                    }
                ]
            };

            chartManager.createBarChart('groupTokenChart', data, {
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function(value) {
                                return new Intl.NumberFormat('zh-CN').format(value);
                            }
                        }
                    }
                }
            });

            this.chartsLoading.groupToken = false;
        },

        // 响应式处理
        handleResize() {
            // 延迟执行以避免频繁调用
            clearTimeout(this.resizeTimeout);
            this.resizeTimeout = setTimeout(() => {
                Object.values(chartManager.charts).forEach(chart => {
                    if (chart && chart.resize) {
                        chart.resize();
                    }
                });
            }, 250);
        },

        // 清理资源
        destroy() {
            this.stopAutoRefresh();
            Object.keys(chartManager.charts).forEach(chartId => {
                chartManager.destroyChart(chartId);
            });
            window.removeEventListener('resize', this.handleResize);
        }
    };
}

// 导出函数供HTML使用
window.enhancedLogsManagement = enhancedLogsManagement;
window.ChartManager = ChartManager;
window.DataExporter = DataExporter;
