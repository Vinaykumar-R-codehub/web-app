# web-app

In all php files change servername, username, password and dbname(database)to your database details


php
$servername = "localhost"; //servername
$username = "root";        //database username 
$password = "";            //database password
$dbname = "food";          //database Name


database part

1st sql commmand:---

CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    item_name VARCHAR(255) NOT NULL,
    item_price DECIMAL(10, 2) NOT NULL,
    customer_name VARCHAR(255) NOT NULL,
    customer_address TEXT NOT NULL,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

2nd sql commmand:-
 
 CREATE TABLE register (
    Name VARCHAR(255) NOT NULL,
    Email VARCHAR(255) NOT NULL,
    Password VARCHAR(255) NOT NULL,
);



