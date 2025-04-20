<?php
// Vérification d'authentification
function requireAuth() {
    if (!isset($_SESSION['user']['id']) || empty($_SESSION['user']['last_login']) || (time() - $_SESSION['user']['last_login'] > 1800)) {
        session_destroy();
        header('Location: /login.php?timeout=1');
        exit;
    }
    
    // Régénération périodique de l'ID de session
    if (!isset($_SESSION['last_regeneration']) || (time() - $_SESSION['last_regeneration'] > 300)) {
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    }
    
    // Mise à jour du timestamp de dernière activité
    $_SESSION['user']['last_login'] = time();
}

// Vérification des permissions
function checkPermission($requiredRole) {
    if ($_SESSION['user']['role'] !== $requiredRole && $_SESSION['user']['role'] !== 'admin') {
        error_log("Tentative d'accès non autorisé par ".$_SESSION['user']['email']." à ".$_SERVER['REQUEST_URI']);
        header('HTTP/1.0 403 Forbidden');
        die('Accès refusé');
    }
}

// Protection CSRF
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken($token) {
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        error_log("Tentative de CSRF détectée");
        die('Token de sécurité invalide');
    }
}