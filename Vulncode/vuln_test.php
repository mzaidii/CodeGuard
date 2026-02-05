<?php
/**
 * Vulnerable PHP Controller - For Security Testing Only
 * DO NOT USE IN PRODUCTION
 */

// Hardcoded Secrets
$db_password = "SuperSecret123!";
$api_key = "sk-1234567890abcdef";
$jwt_secret = "my_jwt_secret_key";

class VulnController {
    
    private $conn;
    
    public function __construct() {
        // Hardcoded database credentials
        $this->conn = new mysqli("localhost", "root", "password123", "mydb");
    }
    
    // SQL Injection - Direct concatenation
    public function getUser($id) {
        $query = "SELECT * FROM users WHERE id = " . $id;
        $result = $this->conn->query($query);
        return $result->fetch_assoc();
    }
    
    // SQL Injection - Using $_GET directly
    public function searchUsers() {
        $name = $_GET['name'];
        $query = "SELECT * FROM users WHERE name LIKE '%" . $name . "%'";
        $result = $this->conn->query($query);
        return $result->fetch_all();
    }
    
    // Command Injection - Using shell_exec
    public function ping($host) {
        $output = shell_exec("ping -c 4 " . $host);
        return $output;
    }
    
    // Command Injection - Using exec
    public function runCommand($cmd) {
        exec($cmd, $output);
        return $output;
    }
    
    // Command Injection - Using system
    public function systemCommand($input) {
        system("ls -la " . $input);
    }
    
    // Code Injection - Using eval
    public function calculate($expression) {
        return eval("return " . $expression . ";");
    }
    
    // XSS - Direct output without encoding
    public function displayMessage($message) {
        echo "<div class='message'>" . $message . "</div>";
    }
    
    // XSS - Using $_GET directly in output
    public function welcomeUser() {
        echo "Welcome, " . $_GET['username'] . "!";
    }
    
    // Path Traversal - Using user input in file path
    public function readFile($filename) {
        $content = file_get_contents("/var/www/files/" . $filename);
        return $content;
    }
    
    // Path Traversal - Include with user input
    public function loadTemplate($template) {
        include($_GET['template'] . ".php");
    }
    
    // Path Traversal - Require with user input
    public function loadModule($module) {
        require($module);
    }
    
    // Insecure Deserialization - Using unserialize on user input
    public function loadSession($data) {
        $session = unserialize($_COOKIE['session_data']);
        return $session;
    }
    
    // Insecure Deserialization - Unserialize from POST
    public function processData() {
        $obj = unserialize($_POST['data']);
        return $obj->execute();
    }
    
    // SSRF - Fetching user-provided URL
    public function fetchUrl($url) {
        $content = file_get_contents($url);
        return $content;
    }
    
    // SSRF - Using curl with user input
    public function curlFetch($url) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);
        return $response;
    }
    
    // Open Redirect - Unvalidated redirect
    public function redirect($url) {
        header("Location: " . $url);
        exit();
    }
    
    // Open Redirect - Using $_GET directly
    public function loginRedirect() {
        header("Location: " . $_GET['redirect']);
        exit();
    }
    
    // XXE - XML parsing without disabling entities
    public function parseXml($xmlData) {
        $doc = new DOMDocument();
        $doc->loadXML($xmlData);
        return $doc->saveXML();
    }
    
    // XXE - SimpleXML without protection
    public function processXml($xml) {
        $data = simplexml_load_string($xml);
        return $data;
    }
    
    // Weak Cryptography - MD5 for passwords
    public function hashPassword($password) {
        return md5($password);
    }
    
    // Weak Cryptography - SHA1 for sensitive data
    public function hashData($data) {
        return sha1($data);
    }
    
    // Insecure Random - Using rand() for tokens
    public function generateToken() {
        $token = rand(100000, 999999);
        return $token;
    }
    
    // Insecure Random - Using mt_rand for security
    public function generateSessionId() {
        return mt_rand() . mt_rand() . mt_rand();
    }
    
    // Missing Authentication - No auth check
    public function deleteUser($id) {
        $query = "DELETE FROM users WHERE id = " . $id;
        $this->conn->query($query);
        return true;
    }
    
    // Missing Authentication - Admin function without auth
    public function adminPanel() {
        return "Welcome to Admin Panel!";
    }
    
    // CSRF - No token validation on POST
    public function updateProfile() {
        $name = $_POST['name'];
        $email = $_POST['email'];
        // Update without CSRF token validation
        $query = "UPDATE users SET name = '$name', email = '$email' WHERE id = " . $_SESSION['user_id'];
        $this->conn->query($query);
    }
    
    // File Upload - No validation
    public function uploadFile() {
        $target = "/var/www/uploads/" . $_FILES['file']['name'];
        move_uploaded_file($_FILES['file']['tmp_name'], $target);
        return $target;
    }
}

// Dangerous global code
if (isset($_GET['action'])) {
    eval($_GET['action']);  // Code Injection
}

// Direct output of user input
echo $_GET['message'];  // XSS
?>
