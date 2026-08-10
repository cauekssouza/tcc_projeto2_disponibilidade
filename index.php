<?php
session_start();

require '../assets/includes/auth_functions.php';
check_logged_in();

// Regenera o ID da sessão para evitar fixation
session_regenerate_id(true);

// Sanitiza o email da sessão (caso exista)
$userEmail = isset($_SESSION['email']) 
    ? filter_var($_SESSION['email'], FILTER_SANITIZE_EMAIL) 
    : null;

// Remove cookie da sessão, se existir
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', [
        'expires' => time() - 3600,
        'path'    => '/',
        'secure'  => true,
        'httponly'=> true,
        'samesite'=> 'Strict'
    ]);
}

// Remove cookie "rememberme" e token no banco
if (isset($_COOKIE['rememberme'])) {

    // Apaga cookie com atributos seguros
    setcookie('rememberme', '', [
        'expires' => time() - 3600,
        'path'    => '/',
        'secure'  => true,
        'httponly'=> true,
        'samesite'=> 'Strict'
    ]);

    // Só prossegue se o email sanitizado for válido
    if ($userEmail) {

        require '../assets/setup/db.inc.php';

        $sql = "DELETE FROM auth_tokens 
                WHERE user_email = ? 
                AND auth_type = 'remember_me'";

        $stmt = mysqli_stmt_init($conn);

        if (mysqli_stmt_prepare($stmt, $sql)) {

            mysqli_stmt_bind_param($stmt, "s", $userEmail);

            if (mysqli_stmt_execute($stmt)) {

                // Atualiza estado da sessão com segurança
                if (isset($_SESSION['auth'])) {
                    $_SESSION['auth'] = 'verified';
                }

            } else {
                // Log de erro (nunca exibir ao usuário)
                error_log("Erro ao executar DELETE em auth_tokens: " . mysqli_error($conn));
            }

        } else {
            error_log("Erro ao preparar statement: " . mysqli_error($conn));
        }
    }
}

// Limpa e destrói a sessão
session_unset();
session_destroy();

// Redireciona com header seguro
header("Location: ../login/");
exit;
