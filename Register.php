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
    $Name = $_POST['Name'];
    $Email = $_POST['Email'];
    $Password = Password_hash($_POST['Password'], PASSWORD_DEFAULT);

    $sql = "INSERT INTO register (Name, Email, Password) VALUES ('$Name', '$Email', '$Password')";

    if ($conn->query($sql) === TRUE) {
        header("Location: login.html");
        exit();
    } else {
        echo "Error: " . $sql . "<br>" . $conn->error;
    }
}

$conn->close();
?>