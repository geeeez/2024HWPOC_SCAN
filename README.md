# 2024HW 1day POC扫描

## 一个漏洞扫描工具

最近特殊时期，把一些暴露出来的1day做了一些收集，写了一个扫描脚本，方便红队进行一些专项漏洞的扫描，主要是不用登录的一些漏洞，以下是该工具涵盖的漏洞列表以及使用方法。

### 涵盖的漏洞

1. **通天星 CMSV6 车载定位监控平台 disable SQL 注入漏洞**
2. **亿赛通数据泄露防护(DLP)系统 NetSecConfigAjax SQL 注入漏洞**
3. **致远在野 nday constDef 接口存在代码执行漏洞**
4. **亿赛通电子文档安全管理系统 NoticeAjax 接口存在 SQL 注入漏洞**
5. **天问物业 ERP 系统 AreaAvatarDownLoad.aspx 任意文件读取漏洞**
6. **福建科立讯通信 指挥调度管理平台 ajax_users.php SQL 注入漏洞**
7. **帆软根据模版注入执行 SQL 语句写文件**
8. **U8cloud 系统 MeasureQueryFrameAction 接口存在 SQL 注入漏洞**
9. **亿赛通数据泄露防护(DLP)系统 NoticeAjax SQL 注入漏洞**
10. **致远 OA fileUpload.do 前台文件上传绕过漏洞**
11. **福建科立讯通信 指挥调度管理平台存在远程命令执行漏洞**
12. **广联达 Linkworks ArchiveWebService XML 实体注入漏洞**
13. **致远互联 AnalyticsCloud 分析云 任意文件读取漏洞**
14. **润乾报表 dataSphereServlet 任意文件读取漏洞**
15. **帆软 FineReport ReportSever Sqlite 注入导致远程代码执行**
16. **Bazarr swaggerui 组件 目录穿越导致任意文件读取漏洞**
17. **泛微 e-cology9 /services/WorkPlanService 前台 SQL 注入**
18. **资管云 comfileup.php 前台文件上传漏洞**
19. **锐捷统一上网行为管理与审计系统 static_convert.php 命令注入漏洞**
20. **赛蓝企业管理系统 DownloadBuilder 任意文件读取漏洞**
21. **赛蓝企业管理系统 ReadTxtLog 任意文件读取漏洞**
22. **赛蓝企业管理系统 GetJSFile 任意文件读取漏洞**
23. **SuiteCRM responseEntryPoint SQL 注入漏洞**
24. **用友 U8CRM import.php 任意文件上传漏洞**

### 使用方法

#### 安装依赖

首先，确保你已经安装了 `requests` 库。如果没有安装，可以使用以下命令进行安装：

```sh
pip install requests
```

#### 运行工具

你可以通过命令行参数指定目标URL或包含目标URL的文件，以及指定要扫描的漏洞编号。

##### 扫描单个URL

```sh
python HWPOCScan.py -u <目标URL> -v <漏洞编号>
```

例如，扫描漏洞编号1的目标URL：

```sh
python HWPOCScan.py -u https://example.com -v 1
```

##### 扫描多个URL

你可以将目标URL写入一个文件，每行一个URL，然后使用以下命令扫描文件中的所有URL：

```sh
python HWPOCScan.py -f <目标URL文件> -v <漏洞编号>
```

例如，扫描文件 `urls.txt` 中的所有URL的漏洞编号1：

```sh
python HWPOCScan.py -f urls.txt -v 1
```

##### 扫描所有漏洞

如果不指定漏洞编号，则会扫描所有漏洞：

```sh
python HWPOCScan.py -u <目标URL>
```

或

```sh
python HWPOCScan.py -f <目标URL文件>
```

例如，扫描目标URL的所有漏洞：

```sh
python HWPOCScan.py -u https://example.com
```

### 免责声明

本工具仅供安全研究和教育用途。使用本工具扫描未经授权的系统可能违反法律法规。用户应自行承担使用本工具的风险和责任。作者不对任何非法使用或由此产生的任何损害负责。