<?php require_once 'app/views/templates/headerPublic.php'?>

<main style="margin-left: 2em">
    <h2>Create Account</h2>

    <form method="POST" action="/create/register">
        <input type="hidden" name="action" value="signup">

        <label>Select Username:</label><br>
        <input type="text" name="username" required><br><br>

        <label>Choose a Password:</label><br>
        <input type="password" name="password" required><br><br>

        <label>Confirm Password:</label><br>
        <input type="password" name="confirm_password" required><br>
        <small style="color: blue;">
            Password must be at least 8 characters long and include at least one uppercase and one lowercase letter.
        </small><br>

        <?php
            if (isset($_SESSION['auth_msg'])) {
                $msg = $_SESSION['auth_msg'];
                unset($_SESSION['auth_msg']);
                echo "<p><strong>" . $msg . "</strong></p>";
            }
        ?>

        <input type="submit" value="Register">
    </form>

    <p>Already have an account?<a href="login"> Login here</a></p>

    <p><a href="index.php">Back to Home</a></p>
</main>

<?php require 'app/views/templates/footer.php'; ?>