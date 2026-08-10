<?php
session_start();

require '../assets/includes/auth_functions.php';
check_logged_in();

// Função segura para remover cookies
function remove_cookie(string $name): void {
    if (isset($_COOKIE[$name])) {
        setcookie(
            $name,
            '',
            [
                'expires'  => time() - 3600,
                'path'     => '/',
                'secure'   => true,      // exige HTTPS
                'httponly' => true,      // evita acesso via JS
                'samesite' => 'Strict'
            ]
        );
    }
}

// Remove cookie de sessão se existir
remove_cookie(session_name());

// Remove cookie "rememberme" e token no banco
if (isset($_COOKIE['rememberme'])) {

    remove_cookie('rememberme');

    // Sanitiza email da sessão antes de usar
    $userEmail = filter_var($_SESSION['email'] ?? '', FILTER_SANITIZE_EMAIL);

    if (!empty($userEmail)) {

        require '../assets/setup/db.inc.php';

        $sql = "DELETE FROM auth_tokens 
                WHERE user_email = ? AND auth_type = 'remember_me'";

        $stmt = mysqli_stmt_init($conn);

        if (mysqli_stmt_prepare($stmt, $sql)) {

            mysqli_stmt_bind_param($stmt, "s", $userEmail);

            mysqli_stmt_execute($stmt);

            // Atualiza estado da sessão com segurança
            if (isset($_SESSION['auth'])) {
                $_SESSION['auth'] = 'verified';
            }
        }
    }
}

// Limpa e destrói a sessão
$_SESSION = [];
session_unset();
session_destroy();

// Redireciona com header seguro
header("Location: ../login/");
exit;
