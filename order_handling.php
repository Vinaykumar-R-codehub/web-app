<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "food";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $itemName = $_POST['item-name'];
    $itemPrice = $_POST['item-price'];
    $customerName = $_POST['customer-name'];
    $customerAddress = $_POST['customer-address'];

    $sql = "INSERT INTO orders (item_name, item_price, customer_name, customer_address) VALUES (?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sdss", $itemName, $itemPrice, $customerName, $customerAddress);

    if ($stmt->execute() === TRUE) {
        echo "Order placed successfully!";
    } else {
        echo "Error: " . $sql . "<br>" . $conn->error;
    }
}

$conn->close();
?>
