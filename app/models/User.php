<?php

class User {

    public $username;
    public $password;
    public $auth = false;

    public function __construct() {
        
    }

    public function test (): array {
      $db = db_connect();
      $statement = $db->prepare("select * from users;");
      $statement->execute();
      $rows = $statement->fetch(PDO::FETCH_ASSOC);
      return $rows;
    }

    public function authenticate($username, $password) {
        /*
         * if username and password good then
         * $this->auth = true;
         */
  		$username = strtolower($username);
  		$db = db_connect();
          $statement = $db->prepare("select * from users WHERE username = :name;");
          $statement->bindValue(':name', $username);
          $statement->execute();
          $rows = $statement->fetch(PDO::FETCH_ASSOC);
  		
  		if (password_verify($password, $rows['password'])) {
  			$_SESSION['auth'] = 1;
  			$_SESSION['username'] = ucwords($username);
  			unset($_SESSION['failedAuth']);
  			header('Location: /home');
  			die;
  		} else {
    			if(isset($_SESSION['failedAuth'])) {
    				$_SESSION['failedAuth'] ++; //increment
    			} else {
    				$_SESSION['failedAuth'] = 1;
    			}
  			header('Location: /login');
  			die;
  		}
    }

  public function create(string $username, string $password): array
  {
      // 1️⃣ Normalise + basic validation
      $username = strtolower(trim($username));

      if (!$this->isPasswordStrong($password)) {
          return [ 'ok' => false,
                   'msg'=> 'Password must be ≥8 chars and contain upper- and lowercase letters.' ];
      }

      // 2️⃣ Check if username already exists
      $db   = db_connect();
      $stmt = $db->prepare('SELECT 1 FROM users WHERE username = :u LIMIT 1');
      $stmt->execute([':u' => $username]);

      if ($stmt->fetch()) {
          return [ 'ok' => false, 'msg' => 'Username already taken.' ];
      }

      // 3️⃣ Insert new user (hashed password!)
      $hash = password_hash($password, PASSWORD_DEFAULT);
      $stmt = $db->prepare(
          'INSERT INTO users (username, password) VALUES (:u, :p)'
      );
      $stmt->execute([':u' => $username, ':p' => $hash]);

      return [ 'ok' => true, 'msg' => 'Account created – please log in.' ];
  }

  private function isPasswordStrong(string $pw): bool{
      return strlen($pw) >= 8 &&
             preg_match('/[A-Z]/', $pw) &&
             preg_match('/[a-z]/', $pw);
  }

}
