<!DOCTYPE html>

<html lang="en-US" dir="ltr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?=$this->e($serviceName); ?></title>
    <link href="css/bootstrap-reboot.min.css" media="screen" rel="stylesheet">
    <link href="css/screen.css" media="screen" rel="stylesheet">
</head>
<body>
    <header>
<?php if (1 < \count($enabledLanguages)): ?>
        <form method="post" action="setLanguage">
<?php foreach ($enabledLanguages as $uiLanguage): ?>
            <button type="submit" name="uiLanguage" value="<?=$this->e($uiLanguage); ?>"><?=$this->e($uiLanguage, 'language_code_to_human'); ?></button>
<?php endforeach; ?>
        </form>
<?php endif; ?>
    </header>
    <main>
        <?=$this->section('content'); ?>
    </main>
    <footer>
        Powered by <a href="https://git.tuxed.net/fkooman/php-saml-sp">php-saml-sp</a>
    </footer>
</body>
</html>
