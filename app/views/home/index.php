<?php require_once 'app/views/templates/header.php'; ?>
<?php
date_default_timezone_set('America/Toronto'); ?>

<style>
    body {
        font-family: Arial, sans-serif;
        background: #f4f6f8;
        margin: 0;
        padding: 0 20px;
    }

    .container {
        max-width: 700px;
        margin: 50px auto;
        background: white;
        padding: 2rem;
        border-radius: 12px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        text-align: center;
    }

    h1 {
        font-size: 2.5rem;
        margin-bottom: 0.2rem;
        color: #333;
    }

    .lead {
        font-size: 1.1rem;
        color: #555;
        margin-bottom: 2rem;
    }

    a {
        display: inline-block;
        padding: 0.6rem 1.2rem;
        background: #007bff;
        color: white;
        text-decoration: none;
        border-radius: 6px;
        transition: background 0.2s ease-in-out;
    }

    a:hover {
        background: #0056b3;
        color: whitesmoke;
    }
</style>

<div class="container">
    <h1>Welcome, <?=$_SESSION['username'] ?>!</h1>
    <p class="lead"><?= date("l, F j, Y, g:i A"); ?></p>

    <p>
        <a href="/logout">Logout</a>
    </p>
</div>

<?php require_once 'app/views/templates/footer.php'; ?>
