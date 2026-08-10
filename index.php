<?php

session_start();

require '../assets/includes/auth_functions.php';
check_logged_in();

/**
 * Função utilitária para remover cookies com segurança.
 */
function clear_cookie(string $name): void {
    if (isset($_COOKIE[$name])) {
        setcookie($name, '', time() - 3600, '/');
    }
}

/**
 * Remove o token "remember me" do banco.
 */
function delete_remember_me_token(mysqli $conn, string $email): void {
    $sql = "DELETE FROM auth_tokens 
            WHERE user_email = ? AND auth_type = 'remember_me'";

    $stmt = mysqli_prepare($conn, $sql);

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);
    }
}

/**
 * Limpa cookies de sessão e remember me.
 */
clear_cookie(session_name());
clear_cookie('rememberme');

/**
 * Se o cookie rememberme existia, remove o token no banco.
 */
if (isset($_COOKIE['rememberme'])) {

    require '../assets/setup/db.inc.php';

    delete_remember_me_token($conn, $_SESSION['email']);

    // Mantém o estado de autenticação consistente
    if (isset($_SESSION['auth'])) {
        $_SESSION['auth'] = 'verified';
    }
}

/**
 * Finaliza a sessão completamente.
 */
session_unset();
session_destroy();

/**
 * Redireciona para a página de login.
 */
header("Location: ../login/");
exit();
