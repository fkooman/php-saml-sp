<?php $this->layout('base'); ?>
<?php $this->start('content'); ?>
    <h2>Welcome</h2>
    <p>
        Welcome to the information page of this SAML SP. If you don't know what
        SAML is, you should not have arrived here! :-)
    </p>

    <h2>Authentication</h2>
    <p>
        You can perform an <a href="wayf?ReturnTo=<?=$this->e($returnTo); ?>">Authentication Test</a> with the 
        configured IdP(s).
    </p>

    <h2>Metadata</h2>
    <p>
        IdPs 😋 SP metadata! Use the URL or the XML below to feed your
        IdP.
    </p>

    <blockquote>
        <code><?=$this->e($metadataUrl); ?></code>
    </blockquote>

    <details>
        <summary>XML</summary>
        <pre><?=$this->e($samlMetadata); ?></pre>
    </details>
<?php $this->stop('content'); ?>
