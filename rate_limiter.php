<?php
// Protecttion contre les attacques à force brute
class RateLimiter {
    private $limit;
    private $timeWindow;
    
    public function __construct($limit = 5, $timeWindow = 60) {
        $this->limit = $limit;
        $this->timeWindow = $timeWindow;
    }
    
    public function check($key) {
        $ip = $_SERVER['REMOTE_ADDR'];
        $cacheKey = "rate_limit_{$ip}_{$key}";
        
        if (!isset($_SESSION[$cacheKey])) {
            $_SESSION[$cacheKey] = [
                'count' => 1,
                'time' => time()
            ];
            return true;
        }
        
        $data = $_SESSION[$cacheKey];
        
        if ((time() - $data['time']) > $this->timeWindow) {
            $_SESSION[$cacheKey] = [
                'count' => 1,
                'time' => time()
            ];
            return true;
        }
        
        if ($data['count'] >= $this->limit) {
            error_log("Rate limit atteint pour $ip sur $key");
            return false;
        }
        
        $_SESSION[$cacheKey]['count']++;
        return true;
    }
}

// Utilisation exemple :
$loginLimiter = new RateLimiter(5, 300); // 5 tentatives en 5 minutes
if (!$loginLimiter->check('login')) {
    header('HTTP/1.1 429 Too Many Requests');
    die('Trop de tentatives de connexion. Veuillez réessayer plus tard.');
}