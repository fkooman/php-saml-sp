<?php $this->layout('base'); ?>
<?php $this->start('content'); ?>
    <h2><?=$this->t('Welcome'); ?></h2>
    <p>
<?=$this->t('This is the information of this SAML SP. If you don\'t know what SAML is, you should not have arrived here! 🤔'); ?>
    </p>

    <h2><?=$this->t('Authentication'); ?></h2>
    <p>
        <?=$this->t('You can perform authentication tests here with the configured IdP(s).'); ?>
    </p>
    <p>
        <a href="wayf?ReturnTo=<?=$this->e($returnTo); ?>"><?=$this->t('Test'); ?></a>
    </p>

    <h2><?=$this->t('Metadata'); ?></h2>
    <p>
<?=$this->t('IdPs ❤️ SP metadata! Use the URL or the XML below to feed your IdP.'); ?>
    </p>

    <blockquote>
        <code><?=$this->e($metadataUrl); ?></code>
    </blockquote>

    <details>
        <summary><?=$this->t('XML'); ?></summary>
        <pre><?=$this->e($samlMetadata); ?></pre>
    </details>
<?php $this->stop('content'); ?>
