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

    public function authenticate($username, $password): array {
        
  		$username = strtolower($username);
        $this->badCountLastMinute($username) . '<br>';
         
  		$db = db_connect();
          $statement = $db->prepare("select * from users WHERE username = :name;");
          $statement->bindValue(':name', $username);
          $statement->execute();
          $rows = $statement->fetch(PDO::FETCH_ASSOC);
  		
  		if (password_verify($password, $rows['password'])) {
            $this->logAttempt($username, 'good');
  			$_SESSION['auth'] = 1;
            unset($_SESSION['locked_until']);
  			$_SESSION['username'] = ucwords($username);
  			unset($_SESSION['failedAuth']);
  			header('Location: /home');
  			die;
  		} else {
            $this->logAttempt($username, 'bad'); 
            $badCount = $this->badCountLastMinute($username);

            if ($badCount >= 3) {  // lock on 3rd failure
                $_SESSION['locked_until'] = time() + 60;
                $_SESSION['auth_msg']     = 'Over 3 attempts. Locked for 60 seconds.';
            } else {
                $_SESSION['auth_msg']     = 'Username or password incorrect.';
            }

            header('Location: /login'); die;
        }
    }
  
  public function create(string $username, string $password): array {
      $username = strtolower(trim($username));

      // Check if username already exists
      $db   = db_connect();
      $stmt = $db->prepare('SELECT 1 FROM users WHERE username = :u LIMIT 1');
      $stmt->execute([':u' => $username]);

      if ($stmt->fetch()) {
          return [ 'ok' => false, 'msg' => 'Username already taken.' ];
      }

      // Check if password pass all the validity rules
      [$ok, $msg] = $this->validatePassword($password);
        if (!$ok) {
            return ['ok' => false, 'msg' => $msg];
        }

      // Insert new user (hashed password!)
      $hash = password_hash($password, PASSWORD_DEFAULT);
      $stmt = $db->prepare(
          'INSERT INTO users (username, password) VALUES (?, ?)');
      $stmt->execute([$username, $hash]);

      return [ 'ok' => true, 'msg' => 'Account created. Proceed to log in.' ];
  }

    
    private function validatePassword(string $pw): array {
        if (strlen($pw) < 8) {
            return [false, 'Password must be at least 8 characters long.'];
        }
        if (!preg_match('/[A-Z]/', $pw)) {
            return [false, 'Password must include at least one uppercase letter.'];
        }
        if (!preg_match('/[a-z]/', $pw)) {
            return [false, 'Password must include at least one lowercase letter.'];
        }
        return [true, ''];
    }
    

    private function logAttempt(string $username, string $outcome): void {
        $db = db_connect();
        $db->prepare(
            'INSERT INTO login_log (username, outcome, logged_at)
             VALUES (?, ?, NOW())'
        )->execute([$username, $outcome]);
    }
    

    private function badCountLastMinute(string $username): int {
        $db = db_connect();
        $stmt = $db->prepare(
            'SELECT COUNT(*) FROM login_log
             WHERE username = ? AND outcome = "bad"
               AND logged_at >= (NOW() - INTERVAL 60 SECOND)'
        );
        $stmt->execute([$username]);
        return (int) $stmt->fetchColumn();
    }
}
