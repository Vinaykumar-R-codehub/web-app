<?php
session_start(); 
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "food";

$conn = new mysqli($servername, $username, $password, $dbname);


if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}


if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $Email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $Password = $_POST['password'];

    $stmt = $conn->prepare("SELECT Password FROM register WHERE Email = ?");
    $stmt->bind_param("s", $Email);
    $stmt->execute();
    $stmt->bind_result($hashed_password);
    $stmt->fetch();

    if ($hashed_password && password_verify($Password, $hashed_password)) {
       
        $_SESSION['email'] = $Email;
        header("Location: home.html");
        exit();
    } else {
        echo "Invalid email or password.";
    }

    $stmt->close();
}

$conn->close();
?>
