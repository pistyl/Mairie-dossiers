<?php
//Validation des données
class InputValidator {
    public static function sanitizeString($input) {
        return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
    }
    
    public static function validateEmail($email) {
        $sanitized = filter_var($email, FILTER_SANITIZE_EMAIL);
        return filter_var($sanitized, FILTER_VALIDATE_EMAIL) ? $sanitized : false;
    }
    
    public static function validatePhone($phone) {
        $cleaned = preg_replace('/[^0-9+]/', '', $phone);
        return (strlen($cleaned) >= 8 && strlen($cleaned) <= 15) ? $cleaned : false;
    }
    
    public static function validateDossierType($type) {
        $allowedTypes = ['Etat civil', 'Urbanisme', 'Social', 'Cimetière', 'Autre'];
        return in_array($type, $allowedTypes) ? $type : false;
    }
}

// Exemple d'utilisation :
$email = InputValidator::validateEmail($_POST['email']);
if (!$email) {
    die('Email invalide');
}