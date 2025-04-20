<?php
//require_once 'security.php';
require_once 'auth_protection.php';
require_once 'rate_limiter.php';

// En haut du fichier
$max_login_attempts = 3;
$lockout_time = 300; // 5 minutes en secondes

// Avant la vérification du mot de passe
if (isset($_SESSION['login_attempts']) && $_SESSION['login_attempts'] >= $max_login_attempts) {
    if (!isset($_SESSION['lockout_time']) || (time() - $_SESSION['lockout_time']) < $lockout_time) {
        $login_error = "Trop de tentatives. Veuillez réessayer dans ".ceil(($lockout_time - (time() - $_SESSION['lockout_time'])) / 60)." minutes";
        // Ne pas continuer la vérification
        return;
    } else {
        // Réinitialiser après la période de verrouillage
        unset($_SESSION['login_attempts']);
        unset($_SESSION['lockout_time']);
    }
}

// Après une tentative échouée
if (!isset($login_success)) {
    $_SESSION['login_attempts'] = ($_SESSION['login_attempts'] ?? 0) + 1;
    if ($_SESSION['login_attempts'] >= $max_login_attempts) {
        $_SESSION['lockout_time'] = time();
    }
}








ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
session_start();

// Configuration de la base de données
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "mairie_dossiers";

// Connexion à la base de données
try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

// Traitement de la connexion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    
    try {
        $stmt = $conn->prepare("SELECT id, nom, prenom, password, role FROM utilisateurs WHERE email = :email LIMIT 1");
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->execute();
        
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            if (password_verify($password, $user['password'])) {
                // Régénération de l'ID de session pour éviter les fixation de session
                session_regenerate_id(true);
                
                $_SESSION = [
                    'user_id' => $user['id'],
                    'user_nom' => $user['nom'],
                    'user_prenom' => $user['prenom'],
                    'user_role' => $user['role'],
                    'user_email' => $email,
                    'logged_in' => true
                ];
                
                header("Location: ".$_SERVER['PHP_SELF']);
                exit;
            } else {
                $login_error = "Mot de passe incorrect";
            }
        } else {
            $login_error = "Aucun compte trouvé avec cet email";
        }
    } catch (PDOException $e) {
        error_log("Erreur de connexion: " . $e->getMessage());
        $login_error = "Erreur technique lors de la connexion";
    }
}




// Vérifier si l'utilisateur est connecté
$is_logged_in = isset($_SESSION['user_id']);
$is_admin = $is_logged_in && $_SESSION['user_role'] === 'admin';

// Traitement de la connexion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $email = $_POST['email'];
    $password = $_POST['password'];
    
    $stmt = $conn->prepare("SELECT id, nom, prenom, password, role FROM utilisateurs WHERE email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_nom'] = $user['nom'];
        $_SESSION['user_prenom'] = $user['prenom'];
        $_SESSION['user_role'] = $user['role'];
        $_SESSION['user_email'] = $email;
        
        $is_logged_in = true;
        $is_admin = $user['role'] === 'admin';
        
        $login_success = "Connexion réussie. Bienvenue " . $user['prenom'] . " " . $user['nom'];
    } else {
        $login_error = "Email ou mot de passe incorrect.";
    }
}

// Traitement de la déconnexion
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: ".str_replace('?logout=1', '', $_SERVER['REQUEST_URI']));
    exit;
}




// Traitement du formulaire de dépôt de dossier
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_dossier'])) {
    $nom = htmlspecialchars($_POST['nom']);
    $prenom = htmlspecialchars($_POST['prenom']);
    $email = htmlspecialchars($_POST['email']);
    $telephone = htmlspecialchars($_POST['telephone']);
    $type_dossier = htmlspecialchars($_POST['type_dossier']);
    $description = htmlspecialchars($_POST['description']);
    
    // Gestion du fichier uploadé
    $file_name = '';
    if (isset($_FILES['piece_jointe']) && $_FILES['piece_jointe']['error'] === UPLOAD_ERR_OK) {
        $upload_dir = 'uploads/';
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }
        $file_name = basename($_FILES['piece_jointe']['name']);
        $file_path = $upload_dir . $file_name;
        move_uploaded_file($_FILES['piece_jointe']['tmp_name'], $file_path);
    }
    
  /*  // Insertion en base de données
    $stmt = $conn->prepare("INSERT INTO dossiers (nom, prenom, email, telephone, type_dossier, description, piece_jointe, statut, date_depot) 
                           VALUES (:nom, :prenom, :email, :telephone, :type_dossier, :description, :piece_jointe, 'Nouveau', NOW())");
    $stmt->bindParam(':nom', $nom);
    $stmt->bindParam(':prenom', $prenom);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':telephone', $telephone);
    $stmt->bindParam(':type_dossier', $type_dossier);
    $stmt->bindParam(':description', $description);
    $stmt->bindParam(':piece_jointe', $file_name);
    $stmt->execute();
    
    $success_message = "Votre dossier a été déposé avec succès. Numéro de suivi: " . $conn->lastInsertId();*/

    // Génération d'un numéro de suivi unique

// Génération du numéro de suivi sécurisé
function generateTrackingNumber($conn) {
    do {
        $numero = 'M-' . strtoupper(bin2hex(random_bytes(3)));
        $stmt = $conn->prepare("SELECT COUNT(*) FROM dossiers WHERE numero_suivi = ?");
        $stmt->execute([$numero]);
        $exists = $stmt->fetchColumn();
    } while ($exists > 0);
    return $numero;
}

$numero_suivi = generateTrackingNumber($conn);

try {
    $stmt = $conn->prepare("INSERT INTO dossiers 
                          (nom, prenom, email, telephone, type_dossier, description, piece_jointe, statut, date_depot, numero_suivi) 
                          VALUES 
                          (:nom, :prenom, :email, :telephone, :type_dossier, :description, :piece_jointe, 'Nouveau', NOW(), :numero_suivi)");
    
    $params = [
        ':nom' => $nom,
        ':prenom' => $prenom,
        ':email' => $email,
        ':telephone' => $telephone,
        ':type_dossier' => $type_dossier,
        ':description' => $description,
        ':piece_jointe' => $file_name,
        ':numero_suivi' => $numero_suivi
    ];
    
    if ($stmt->execute($params)) {
        $success_message = "Dossier enregistré. Votre numéro: <strong>$numero_suivi</strong>";
        
        // Vérification dans la base
        $check = $conn->prepare("SELECT numero_suivi FROM dossiers WHERE id = ?");
        $check->execute([$conn->lastInsertId()]);
        $saved_number = $check->fetchColumn();
        
        if ($saved_number !== $numero_suivi) {
            error_log("Incohérence: $numero_suivi généré mais $saved_number sauvegardé");
        }
    }
} catch (PDOException $e) {
    error_log("Erreur DB: " . $e->getMessage());
    $error_message = "Erreur technique. Contactez l'administration avec ces informations: " . $numero_suivi;
}

// Insertion en base de données
$stmt = $conn->prepare("INSERT INTO dossiers (nom, prenom, email, telephone, type_dossier, description, piece_jointe, statut, date_depot, numero_suivi) 
                       VALUES (:nom, :prenom, :email, :telephone, :type_dossier, :description, :piece_jointe, 'Nouveau', NOW(), :numero_suivi)");
$stmt->bindParam(':numero_suivi', $numero_suivi);
// ... autres bindParam
//$stmt->execute();

$success_message = "Votre dossier a été déposé avec succès. Votre numéro de suivi est : <strong>$numero_suivi</strong>";

// Envoi d'email de confirmation
if ($stmt->rowCount() > 0) {
    $to = $email;
    $subject = "Votre dossier a été déposé - Mairie";
    $message = "
    <html>
    <head>
        <title>Confirmation de dépôt de dossier</title>
    </head>
    <body>
        <p>Bonjour ".htmlspecialchars($prenom)." ".htmlspecialchars($nom).",</p>
        <p>Votre dossier a bien été enregistré sous le numéro de suivi : <strong>$numero_suivi</strong></p>
        <p>Type de dossier : ".htmlspecialchars($type_dossier)."</p>
        <p>Vous pouvez suivre l'avancement de votre dossier à tout moment sur notre plateforme.</p>
        <p>Cordialement,<br>Le service administratif de la mairie</p>
    </body>
    </html>
    ";
    
    $headers = "MIME-Version: 1.0\r\n";
    $headers .= "Content-type: text/html; charset=UTF-8\r\n";
    $headers .= "From: no-reply@mairie.fr\r\n";
    
    mail($to, $subject, $message, $headers);
}

}

// Traitement de la modification du statut par l'agent
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_status']) && $is_admin) {
    $dossier_id = $_POST['dossier_id'];
    $new_status = $_POST['new_status'];
    $commentaire = htmlspecialchars($_POST['commentaire']);
    
    $stmt = $conn->prepare("UPDATE dossiers SET statut = :statut, commentaire = :commentaire, date_traitement = NOW(), agent_id = :agent_id WHERE id = :id");
    $stmt->bindParam(':statut', $new_status);
    $stmt->bindParam(':commentaire', $commentaire);
    $stmt->bindParam(':agent_id', $_SESSION['user_id']);
    $stmt->bindParam(':id', $dossier_id);
    $stmt->execute();
    
    $admin_success = "Statut du dossier #$dossier_id mis à jour avec succès.";
}

// Récupération des dossiers pour le tableau de bord
$dossiers = [];
if ($is_admin) {
    $stmt = $conn->query("SELECT d.*, u.nom as agent_nom, u.prenom as agent_prenom 
                         FROM dossiers d 
                         LEFT JOIN utilisateurs u ON d.agent_id = u.id 
                         ORDER BY date_depot DESC");
    $dossiers = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Statistiques pour le tableau de bord
$stats = [
    'total' => 0,
    'nouveau' => 0,
    'en_cours' => 0,
    'traite' => 0,
    'rejete' => 0
];

if ($dossiers) {
    $stats['total'] = count($dossiers);
    foreach ($dossiers as $dossier) {
        switch ($dossier['statut']) {
            case 'Nouveau': $stats['nouveau']++; break;
            case 'En cours': $stats['en_cours']++; break;
            case 'Traité': $stats['traite']++; break;
            case 'Rejeté': $stats['rejete']++; break;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestion des Dossiers - Mairie</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body class="bg-gray-100">
    
    <div class="container mx-auto px-4 py-8">
        <!-- En-tête avec gestion de connexion -->
        <header class="bg-blue-800 text-white p-6 rounded-lg shadow-md mb-8 relative">
            <h1 class="text-3xl font-bold">Service Administratif - Mairie</h1>
            <p class="mt-2">Dépôt et suivi des dossiers administratifs</p>
            
            <?php if ($is_logged_in): ?>
                <div class="absolute top-4 right-4 flex items-center space-x-4">
                    <span class="text-blue-200">Connecté en tant que <?php echo $_SESSION['user_prenom'] . ' ' . $_SESSION['user_nom']; ?></span>
                    <a href="?logout=1" class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm">
                        <i class="fas fa-sign-out-alt mr-1"></i> Déconnexion
                    </a>
                </div>
            <?php else: ?>
                <button onclick="document.getElementById('login-modal').classList.remove('hidden')" 
                        class="absolute top-4 right-4 bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded text-sm">
                    <i class="fas fa-sign-in-alt mr-1"></i> Connexion agents
                </button>
            <?php endif; ?>
        </header>

        <!-- Modal de connexion -->
        <div id="login-modal" class="<?php echo isset($login_error) ? '' : 'hidden'; ?> fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full">
            <div class="relative top-20 mx-auto p-5 border w-11/12 md:w-1/3 shadow-lg rounded-md bg-white">
                <form method="POST" action="">
                    <div class="flex justify-between items-center border-b pb-2">
                        <h3 class="text-lg font-medium">Connexion agents administratifs</h3>
                        <button type="button" onclick="document.getElementById('login-modal').classList.add('hidden')" class="text-gray-500 hover:text-gray-700">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    
                    <?php if (isset($login_error)): ?>
                        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mt-3">
                            <?php echo $login_error; ?>
                        </div>
                    <?php endif; ?>
                    
                    <?php if (isset($login_success)): ?>
                        <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mt-3">
                            <?php echo $login_success; ?>
                        </div>
                    <?php endif; ?>
                    
                    <div class="mt-4 space-y-4">
                        <div>
                            <label for="email" class="block text-sm font-medium text-gray-700">Email</label>
                            <input type="email" id="email" name="email" required class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                        </div>
                        
                        <div>
                            <label for="password" class="block text-sm font-medium text-gray-700">Mot de passe</label>
                            <input type="password" id="password" name="password" required class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                        </div>
                    </div>
                    <div class="mt-4 flex justify-end space-x-3">
                        <button type="button" onclick="document.getElementById('login-modal').classList.add('hidden')" class="bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-2 px-4 rounded">
                            Annuler
                        </button>
                        <button type="submit" name="login" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
                            Se connecter
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Navigation -->
        <nav class="flex flex-wrap justify-center gap-4 mb-8">
            <a href="#depot" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition">Déposer un dossier</a>
            <a href="#suivi" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg transition">Suivi des dossiers</a>
            <?php if ($is_admin): ?>
                <a href="#tableau-de-bord" class="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition">Tableau de bord</a>
            <?php endif; ?>
        </nav>

        <!-- Section de dépôt de dossier -->
        <section id="depot" class="bg-white p-6 rounded-lg shadow-md mb-8">
            <h2 class="text-2xl font-semibold mb-4 text-blue-800 border-b pb-2">Déposer un nouveau dossier</h2>
            
            <?php if (isset($success_message)): ?>
                <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
                    <?php echo $success_message; ?>
                </div>
            <?php endif; ?>
            
            <form action="" method="POST" enctype="multipart/form-data" class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <label for="nom" class="block text-sm font-medium text-gray-700">Nom *</label>
                    <input type="text" id="nom" name="nom" required class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                </div>
                
                <div>
                    <label for="prenom" class="block text-sm font-medium text-gray-700">Prénom *</label>
                    <input type="text" id="prenom" name="prenom" required class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                </div>
                
                <div>
                    <label for="email" class="block text-sm font-medium text-gray-700">Email *</label>
                    <input type="email" id="email" name="email" required class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                </div>
                
                <div>
                    <label for="telephone" class="block text-sm font-medium text-gray-700">Téléphone</label>
                    <input type="tel" id="telephone" name="telephone" class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                </div>
                
                <div class="md:col-span-2">
                    <label for="type_dossier" class="block text-sm font-medium text-gray-700">Type de dossier *</label>
                    <select id="type_dossier" name="type_dossier" required class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                        <option value="">Sélectionnez un type</option>
                        <option value="Etat civil">Etat civil (naissance, mariage, décès)</option>
                        <option value="Urbanisme">Urbanisme (permis de construire, déclaration préalable)</option>
                        <option value="Social">Social (aide sociale, RSA, logement)</option>
                        <option value="Cimetière">Cimetière (concession, exhumation)</option>
                        <option value="Autre">Autre</option>
                    </select>
                </div>
                
                <div class="md:col-span-2">
                    <label for="description" class="block text-sm font-medium text-gray-700">Description *</label>
                    <textarea id="description" name="description" rows="3" required class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500"></textarea>
                </div>
                
                <div class="md:col-span-2">
                    <label for="piece_jointe" class="block text-sm font-medium text-gray-700">Pièce jointe (si nécessaire)</label>
                    <input type="file" id="piece_jointe" name="piece_jointe" class="mt-1 block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100">
                    <p class="mt-1 text-sm text-gray-500">Formats acceptés: PDF, JPG, PNG (max 5Mo)</p>
                </div>
                
                <div class="md:col-span-2">
                    <button type="submit" name="submit_dossier" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline transition">
                        <i class="fas fa-paper-plane mr-2"></i> Soumettre le dossier
                    </button>
                </div>
            </form>
        </section>

        <!-- Section de suivi pour les citoyens -->
        <section id="suivi" class="bg-white p-6 rounded-lg shadow-md mb-8">
    <h2 class="text-2xl font-semibold mb-4 text-green-800 border-b pb-2">Suivi de votre dossier</h2>
    
    <?php
    // Traitement du formulaire de suivi
    $suivi_result = null;
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['check_status'])) {
        $numero_dossier = trim($_POST['numero_dossier']);
        $email = trim($_POST['email']);
        
        try {
            $stmt = $conn->prepare("SELECT * FROM dossiers WHERE numero_suivi = :numero AND email = :email");
            $stmt->bindParam(':numero', $numero_dossier);
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            
            $suivi_result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$suivi_result) {
                echo '<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                        Aucun dossier trouvé avec ces informations. Vérifiez votre numéro de suivi et email.
                      </div>';
            }
        } catch(PDOException $e) {
            echo '<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                    Erreur lors de la recherche du dossier: '.$e->getMessage().'
                  </div>';
        }
    }
    ?>
    
    <form method="POST" action="#suivi" class="max-w-md mx-auto">
        <div class="mb-4">
            <label for="numero_dossier" class="block text-sm font-medium text-gray-700">Numéro de suivi *</label>
            <input type="text" id="numero_dossier" name="numero_dossier" required 
                   class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-green-500 focus:border-green-500"
                   value="<?= isset($_POST['numero_dossier']) ? htmlspecialchars($_POST['numero_dossier']) : '' ?>">
        </div>
        <div class="mb-4">
            <label for="email" class="block text-sm font-medium text-gray-700">Email de dépôt *</label>
            <input type="email" id="email" name="email" required 
                   class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-green-500 focus:border-green-500"
                   value="<?= isset($_POST['email']) ? htmlspecialchars($_POST['email']) : '' ?>">
        </div>
        <button type="submit" name="check_status" class="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline transition">
            <i class="fas fa-search mr-2"></i> Vérifier le statut
        </button>
    </form>
    
    <?php if ($suivi_result): ?>
    <div class="mt-8 bg-gray-50 p-6 rounded-lg border border-gray-200">
        <h3 class="text-xl font-semibold mb-4">Informations sur votre dossier</h3>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
                <h4 class="font-medium text-gray-700">Numéro de suivi</h4>
                <p><?= htmlspecialchars($suivi_result['numero_suivi']) ?></p>
            </div>
            <div>
                <h4 class="font-medium text-gray-700">Statut</h4>
                <?php 
                $status_classes = [
                    'Nouveau' => 'bg-yellow-100 text-yellow-800',
                    'En cours' => 'bg-orange-100 text-orange-800',
                    'Traité' => 'bg-green-100 text-green-800',
                    'Rejeté' => 'bg-red-100 text-red-800'
                ];
                ?>
                <span class="px-3 py-1 inline-flex text-sm leading-5 font-semibold rounded-full <?= $status_classes[$suivi_result['statut']] ?? 'bg-gray-100 text-gray-800' ?>">
                    <?= htmlspecialchars($suivi_result['statut']) ?>
                </span>
            </div>
        </div>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
                <h4 class="font-medium text-gray-700">Type de dossier</h4>
                <p><?= htmlspecialchars($suivi_result['type_dossier']) ?></p>
            </div>
            <div>
                <h4 class="font-medium text-gray-700">Date de dépôt</h4>
                <p><?= date('d/m/Y H:i', strtotime($suivi_result['date_depot'])) ?></p>
            </div>
        </div>
        
        <?php if ($suivi_result['date_traitement']): ?>
        <div class="mb-4">
            <h4 class="font-medium text-gray-700">Date de traitement</h4>
            <p><?= date('d/m/Y H:i', strtotime($suivi_result['date_traitement'])) ?></p>
        </div>
        <?php endif; ?>
        
        <?php if ($suivi_result['commentaire']): ?>
        <div class="bg-blue-50 p-4 rounded border border-blue-100">
            <h4 class="font-medium text-gray-700">Commentaire de l'administration</h4>
            <p class="whitespace-pre-line"><?= nl2br(htmlspecialchars($suivi_result['commentaire'])) ?></p>
        </div>
        <?php endif; ?>
        
        <?php if ($suivi_result['piece_jointe']): ?>
        <div class="mt-4">
            <h4 class="font-medium text-gray-700">Pièce jointe</h4>
            <a href="uploads/<?= htmlspecialchars($suivi_result['piece_jointe']) ?>" 
               target="_blank" 
               class="text-blue-600 hover:underline inline-flex items-center">
                <i class="fas fa-file-pdf mr-2"></i> Télécharger le document
            </a>
        </div>
        <?php endif; ?>
    </div>
    <?php endif; ?>
    
    <div class="mt-8 bg-gray-50 p-4 rounded-lg">
        <h3 class="text-lg font-medium text-gray-900 mb-2">Explications des statuts :</h3>
        <ul class="list-disc pl-5 space-y-1">
            <li><span class="font-semibold">Nouveau</span> : Votre dossier a été reçu et est en attente de traitement.</li>
            <li><span class="font-semibold">En cours</span> : Votre dossier est en cours d'instruction par nos services.</li>
            <li><span class="font-semibold">Traité</span> : Votre dossier a été traité avec succès.</li>
            <li><span class="font-semibold">Rejeté</span> : Votre dossier n'a pas pu être traité (des informations supplémentaires peuvent être nécessaires).</li>
        </ul>
    </div>
</section>

        <!-- Section tableau de bord pour les agents -->
        <?php if ($is_admin): ?>
        <section id="tableau-de-bord" class="bg-white p-6 rounded-lg shadow-md">
            <h2 class="text-2xl font-semibold mb-4 text-purple-800 border-b pb-2">Tableau de bord administratif</h2>
            
            <?php if (isset($admin_success)): ?>
                <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
                    <?php echo $admin_success; ?>
                </div>
            <?php endif; ?>
            
            <!-- Statistiques -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div class="bg-blue-100 p-4 rounded-lg border border-blue-200">
                    <h3 class="font-medium text-blue-800">Total dossiers</h3>
                    <p class="text-3xl font-bold text-blue-600"><?php echo $stats['total']; ?></p>
                </div>
                <div class="bg-yellow-100 p-4 rounded-lg border border-yellow-200">
                    <h3 class="font-medium text-yellow-800">Nouveaux</h3>
                    <p class="text-3xl font-bold text-yellow-600"><?php echo $stats['nouveau']; ?></p>
                </div>
                <div class="bg-orange-100 p-4 rounded-lg border border-orange-200">
                    <h3 class="font-medium text-orange-800">En cours</h3>
                    <p class="text-3xl font-bold text-orange-600"><?php echo $stats['en_cours']; ?></p>
                </div>
                <div class="bg-green-100 p-4 rounded-lg border border-green-200">
                    <h3 class="font-medium text-green-800">Traités</h3>
                    <p class="text-3xl font-bold text-green-600"><?php echo $stats['traite']; ?></p>
                </div>
            </div>
            
            <!-- Liste des dossiers -->
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Citoyen</th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date dépôt</th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Statut</th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Agent</th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php foreach ($dossiers as $dossier): ?>
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">#<?php echo $dossier['id']; ?></td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                <?php echo $dossier['prenom'] . ' ' . $dossier['nom']; ?>
                                <div class="text-xs text-gray-400"><?php echo $dossier['email']; ?></div>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo $dossier['type_dossier']; ?></td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo date('d/m/Y', strtotime($dossier['date_depot'])); ?></td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <?php 
                                $status_classes = [
                                    'Nouveau' => 'bg-yellow-100 text-yellow-800',
                                    'En cours' => 'bg-orange-100 text-orange-800',
                                    'Traité' => 'bg-green-100 text-green-800',
                                    'Rejeté' => 'bg-red-100 text-red-800'
                                ];
                                ?>
                                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full <?php echo $status_classes[$dossier['statut'] ?? 'bg-gray-100 text-gray-800']; ?>">
                                    <?php echo $dossier['statut']; ?>
                                </span>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                <?php if ($dossier['agent_id']): ?>
                                    <?php echo $dossier['agent_prenom'] . ' ' . $dossier['agent_nom']; ?>
                                <?php else: ?>
                                    <span class="text-gray-400">Non assigné</span>
                                <?php endif; ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                <button onclick="document.getElementById('modal-<?php echo $dossier['id']; ?>').classList.remove('hidden')" class="text-blue-600 hover:text-blue-900 mr-3">Voir</button>
                                <button onclick="document.getElementById('edit-modal-<?php echo $dossier['id']; ?>').classList.remove('hidden')" class="text-purple-600 hover:text-purple-900">Modifier</button>
                            </td>
                        </tr>
                        
                        <!-- Modal de visualisation -->
                        <div id="modal-<?php echo $dossier['id']; ?>" class="hidden fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full">
                            <div class="relative top-20 mx-auto p-5 border w-11/12 md:w-2/3 shadow-lg rounded-md bg-white">
                                <div class="flex justify-between items-center border-b pb-2">
                                    <h3 class="text-lg font-medium">Dossier #<?php echo $dossier['id']; ?></h3>
                                    <button onclick="document.getElementById('modal-<?php echo $dossier['id']; ?>').classList.add('hidden')" class="text-gray-500 hover:text-gray-700">
                                        <i class="fas fa-times"></i>
                                    </button>
                                </div>
                                <div class="mt-4 space-y-4">
                                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <h4 class="font-medium">Citoyen</h4>
                                            <p><?php echo $dossier['prenom'] . ' ' . $dossier['nom']; ?></p>
                                        </div>
                                        <div>
                                            <h4 class="font-medium">Contact</h4>
                                            <p><?php echo $dossier['email']; ?></p>
                                            <p><?php echo $dossier['telephone']; ?></p>
                                        </div>
                                    </div>
                                    <div>
                                        <h4 class="font-medium">Type de dossier</h4>
                                        <p><?php echo $dossier['type_dossier']; ?></p>
                                    </div>
                                    <div>
                                        <h4 class="font-medium">Description</h4>
                                        <p class="whitespace-pre-line"><?php echo $dossier['description']; ?></p>
                                    </div>
                                    <?php if ($dossier['piece_jointe']): ?>
                                    <div>
                                        <h4 class="font-medium">Pièce jointe</h4>
                                        <a href="uploads/<?php echo $dossier['piece_jointe']; ?>" target="_blank" class="text-blue-600 hover:underline">
                                            <i class="fas fa-file-alt mr-1"></i> <?php echo $dossier['piece_jointe']; ?>
                                        </a>
                                    </div>
                                    <?php endif; ?>
                                    <?php if ($dossier['commentaire']): ?>
                                    <div class="bg-gray-50 p-3 rounded">
                                        <h4 class="font-medium">Commentaire de l'agent</h4>
                                        <p class="whitespace-pre-line"><?php echo $dossier['commentaire']; ?></p>
                                        <?php if ($dossier['agent_id']): ?>
                                        <p class="text-sm text-gray-500 mt-1">- <?php echo $dossier['agent_prenom'] . ' ' . $dossier['agent_nom']; ?></p>
                                        <?php endif; ?>
                                    </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Modal de modification -->
                        <div id="edit-modal-<?php echo $dossier['id']; ?>" class="hidden fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full">
                            <div class="relative top-20 mx-auto p-5 border w-11/12 md:w-1/2 shadow-lg rounded-md bg-white">
                                <form method="POST" action="">
                                    <div class="flex justify-between items-center border-b pb-2">
                                        <h3 class="text-lg font-medium">Modifier dossier #<?php echo $dossier['id']; ?></h3>
                                        <button type="button" onclick="document.getElementById('edit-modal-<?php echo $dossier['id']; ?>').classList.add('hidden')" class="text-gray-500 hover:text-gray-700">
                                            <i class="fas fa-times"></i>
                                        </button>
                                    </div>
                                    <div class="mt-4 space-y-4">
                                        <input type="hidden" name="dossier_id" value="<?php echo $dossier['id']; ?>">
                                        
                                        <div>
                                            <label for="new_status" class="block text-sm font-medium text-gray-700">Nouveau statut</label>
                                            <select id="new_status" name="new_status" required class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-purple-500 focus:border-purple-500">
                                                <option value="Nouveau" <?php echo $dossier['statut'] === 'Nouveau' ? 'selected' : ''; ?>>Nouveau</option>
                                                <option value="En cours" <?php echo $dossier['statut'] === 'En cours' ? 'selected' : ''; ?>>En cours</option>
                                                <option value="Traité" <?php echo $dossier['statut'] === 'Traité' ? 'selected' : ''; ?>>Traité</option>
                                                <option value="Rejeté" <?php echo $dossier['statut'] === 'Rejeté' ? 'selected' : ''; ?>>Rejeté</option>
                                            </select>
                                        </div>
                                        
                                        <div>
                                            <label for="commentaire" class="block text-sm font-medium text-gray-700">Commentaire</label>
                                            <textarea id="commentaire" name="commentaire" rows="3" class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-purple-500 focus:border-purple-500"><?php echo $dossier['commentaire'] ?? ''; ?></textarea>
                                        </div>
                                    </div>
                                    <div class="mt-4 flex justify-end space-x-3">
                                        <button type="button" onclick="document.getElementById('edit-modal-<?php echo $dossier['id']; ?>').classList.add('hidden')" class="bg-gray-200 hover:bg-gray-300 text-gray-800 font-bold py-2 px-4 rounded">
                                            Annuler
                                        </button>
                                        <button type="submit" name="update_status" class="bg-purple-600 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded">
                                            Enregistrer
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </section>
        <?php endif; ?>
    </div>

    <!-- Pied de page -->
    <footer class="bg-gray-800 text-white p-6 mt-12">
        <div class="container mx-auto px-4">
            <div class="flex flex-col md:flex-row justify-between items-center">
                <div class="mb-4 md:mb-0">
                    <h3 class="text-xl font-bold">Mairie - Service Administratif</h3>
                    <p class="mt-1 text-gray-400">Village de Yene Guedj, en face le poste de santé</p>
                </div>
                <div class="flex space-x-4">
                    <a href="#" class="text-gray-400 hover:text-white transition">
                        <i class="fas fa-phone-alt"></i> 33 000 00 00
                    </a>
                    <a href="#" class="text-gray-400 hover:text-white transition">
                        <i class="fas fa-envelope"></i> contact@mairie.sn
                    </a>
                </div>
            </div>
            <div class="mt-6 pt-6 border-t border-gray-700 text-center text-gray-400 text-sm">
                <p>© <?php echo date('Y'); ?> Mairie. Tous droits réservés.</p>
            </div>
        </div>
    </footer>
</body>
</html>