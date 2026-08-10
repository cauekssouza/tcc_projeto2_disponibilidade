<?php

session_start();

require '../assets/includes/auth_functions.php';
check_logged_in();

// Função utilitária para remover cookies com segurança
function clear_cookie(string $name): void {
    if (isset($_COOKIE[$name])) {
        setcookie($name, '', time() - 3600, '/', '', false, true);
    }
}

// Remove cookies de sessão e remember-me
clear_cookie(session_name());
clear_cookie('rememberme');

// Se o usuário estava usando "remember me", remove o token do banco
if (isset($_COOKIE['rememberme'])) {

    require '../assets/setup/db.inc.php';

    $sql = "DELETE FROM auth_tokens 
            WHERE user_email = ? 
              AND auth_type = 'remember_me'";

    $stmt = mysqli_prepare($conn, $sql);

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "s", $_SESSION['email']);
        mysqli_stmt_execute($stmt);
    }

    // Mantém o estado de autenticação consistente
    if (isset($_SESSION['auth'])) {
        $_SESSION['auth'] = 'verified';
    }
}

// Finaliza sessão
session_unset();
session_destroy();

// Redireciona para login
header("Location: ../login/");
exit();
