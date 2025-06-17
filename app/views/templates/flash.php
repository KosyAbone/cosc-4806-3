<?php $flash = $flash ?? null; ?>

<?php if (!empty($flash)): ?>
    <div class="alert alert-danger">
        <?= htmlspecialchars($flash) ?>
    </div>
<?php endif; ?>
