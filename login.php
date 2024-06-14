<?php
session_start(); // Start a new session or resume the existing session

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "food";

// Create a connection to the database
$conn = new mysqli($servername, $username, $password, $dbname);

// Check the connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}


if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitize input
    $Email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $Password = $_POST['password'];

    // Prepare and bind the SQL statement
    $stmt = $conn->prepare("SELECT Password FROM register WHERE Email = ?");
    $stmt->bind_param("s", $Email);
    $stmt->execute();
    $stmt->bind_result($hashed_password);
    $stmt->fetch();

    if ($hashed_password && password_verify($Password, $hashed_password)) {
        // Store user information in the session
        $_SESSION['email'] = $Email;

        // Redirect to home page
        header("Location: home.html");
        exit();
    } else {
        echo "Invalid email or password.";
    }

    $stmt->close();
}

$conn->close();
?>
