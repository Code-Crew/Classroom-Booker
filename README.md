## Simplified Installation

This applicaton has already been setup with some basic default values applied to the database.

First off you will need to extract the archive:

```
cp crbs.tar.bx2 /var/www/
```

The above location works for most systems however it is ultimately up to your choosing

```
tar -xvjf crbs.tar.bz2
```

This will creat a directory called ```classroombookings``` in your current directory

Next you will want to enter the directory and import the sql file (as root sql user as this will 
create a database named ```crbs```

```
mysql -u root -p < crbs.db.sql
```

Next you will need to grant an sql user full permissions to the database and apply that information to the database config

```
vi <path to classroombookings>/system/applcation/config/database.php
```

And add the correct user name and password.

Finally maake sure your apache server is pointing to the right directory.

Load your favorite browser and check.


### Admin User information

These have been prefilled and can be changed. The process for allowing access to change the password 
is editing ```system/application/config/config.php``` and setting ```$config['allow_passwords'] ``` to ```1```

The current username and password for the admin user is:

```
username:   codecrew
password:   test
```

