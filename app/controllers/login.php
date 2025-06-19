<?php

class Login extends Controller {

    public function index() {
			$flash = $_SESSION['auth_msg'] ?? null;
			unset($_SESSION['auth_msg']);
			$this->view('login/index', ['flash' => $flash]);
    }
    
    public function verify(){
			if (isset($_SESSION['locked_until']) && $_SESSION['locked_until'] > time()) {
					$_SESSION['auth_msg'] = 'You are Locked out. Please wait a few seconds.';
					header('Location: /login');
					exit;
			}
			
			$username = $_REQUEST['username'];
			$password = $_REQUEST['password'];
		
			$user = $this->model('User');
			$result = $user->authenticate($username, $password); 

			$_SESSION['auth_msg'] = $result['msg'];

			header('Location: ' . ($result['ok'] ? '/home' : '/login'));
			exit;
    }

}
