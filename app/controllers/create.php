<?php

class Create extends Controller {
   
    public function index(){
        $flash = $_SESSION['auth_msg'] ?? null;
        unset($_SESSION['auth_msg']);
        $this->view('create/index', ['flash' => $flash]);
    }


    public function register() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            header('Location: /create');
            exit;
        }

        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        if ($password !== $confirmPassword) {
            $_SESSION['auth_msg'] = 'Passwords do not match.';
            header('Location: /create');
            exit;
        }

        $user   = $this->model('User');
        $result = $user->create($username, $password);

        $_SESSION['auth_msg'] = $result['msg'];

        header('Location: ' . ($result['ok'] ? '/login' : '/create'));
        
        exit;
    }
}
