<?php

session_start();

require '../assets/includes/auth_functions.php';
check_logged_in();

/**
 * Função utilitária para remover cookies com segurança
 */
function delete_cookie(string $name): void {
    if (isset($_COOKIE[$name])) {
        setcookie($name, '', time() - 3600, '/');
    }
}

/**
 * Remove o cookie de sessão, se existir
 */
delete_cookie(session_name());

/**
 * Remove o cookie "rememberme" e o token correspondente no banco
 */
if (isset($_COOKIE['rememberme'])) {

    delete_cookie('rememberme');

    require '../assets/setup/db.inc.php';

    $sql = "DELETE FROM auth_tokens 
            WHERE user_email = ? AND auth_type = 'remember_me'";

    $stmt = mysqli_prepare($conn, $sql);

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "s", $_SESSION['email']);
        mysqli_stmt_execute($stmt);
    }

    // Mantém coerência com o fluxo de autenticação
    if (isset($_SESSION['auth'])) {
        $_SESSION['auth'] = 'verified';
    }
}

/**
 * Finaliza a sessão completamente
 */
session_unset();
session_destroy();

/**
 * Redireciona para a página de login
 */
header("Location: ../login/");
exit();
