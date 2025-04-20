<?php
// Protection contre les attaques
header_remove('X-Powered-By'); // Cache le header PHP
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

// Désactivation des erreurs en production
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__.'/security.log');

// Configuration sécurisée des sessions
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', '1'); // Activez seulement avec HTTPS
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
ini_set('session.gc_maxlifetime', '1800'); // 30 minutes

// Protection contre les attaques par injection
if (isset($_SERVER['QUERY_STRING']) && preg_match('/union|select|insert|update|delete|drop|--|#|\/\*|\*\/|script|alert/i', $_SERVER['QUERY_STRING'])) {
    error_log("Tentative d'injection SQL détectée: ".$_SERVER['QUERY_STRING']);
    die('Requête bloquée pour raisons de sécurité');
}

// Protection contre les fichiers malveillants
function sanitizeUploadedFile(array $file): bool {
    $allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
    $maxSize = 5 * 1024 * 1024; // 5MB
    
    if (!in_array($file['type'], $allowedTypes)) {
        error_log("Type de fichier non autorisé: ".$file['type']);
        return false;
    }
    
    if ($file['size'] > $maxSize) {
        error_log("Fichier trop volumineux: ".$file['size']);
        return false;
    }
    
    $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
    if (!in_array(strtolower($extension), ['pdf', 'jpg', 'jpeg', 'png'])) {
        error_log("Extension de fichier non autorisée: ".$extension);
        return false;
    }
    
    return true;
}

// Enregistrement des activités suspectes
function logSecurityEvent($event, $severity = 'warning') {
    $log = sprintf(
        "[%s] [%s] %s - IP: %s - UserAgent: %s\n",
        date('Y-m-d H:i:s'),
        $severity,
        $event,
        $_SERVER['REMOTE_ADDR'],
        $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
    );
    
    file_put_contents(__DIR__.'/security.log', $log, FILE_APPEND);
    
    if ($severity === 'critical') {
        // Envoyer une alerte par email
        mail('admin@mairie.fr', 'Alerte sécurité', $log);
    }
}