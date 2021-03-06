<?php $this->layout('base'); ?>
<?php $this->start('content'); ?>
    <h2><?=$this->t('Welcome'); ?></h2>
    <p>
<?=$this->t('This is the information page of this SAML SP. If you don\'t know what SAML is, you should not have arrived here! 🤔'); ?>
    </p>

<?php if (!$secureCookie): ?>
    <p class="warning">
<?=$this->t('Secure Cookies are disabled. This is ONLY appropriate for development!'); ?>
    </p>
<?php endif; ?>

<?php if (!$decryptionSupport): ?>
    <p class="warning">
<?=$this->t('PHP >= 7.1 is required for <code>&lt;EncryptedAssertion&gt;</code> support.'); ?>
    </p>
<?php endif; ?>

    <h2><?=$this->t('Authentication'); ?></h2>
    <p>
        <?=$this->t('You can perform authentication tests here with the configured IdP(s).'); ?>
    </p>
    <p>
        <a href="info"><?=$this->t('Test'); ?></a>
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
