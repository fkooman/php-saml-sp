<?php $this->layout('base'); ?>
<?php $this->start('content'); ?>
    <h2><?=$this->t('Assertion'); ?></h2>
    <dl>
        <dt><?=$this->t('Issuer'); ?></dt>
        <dd><code><?=$this->e($samlAssertion->getIssuer()); ?></code></dd>

<?php if (null !== $nameId = $samlAssertion->getNameId()): ?>
        <dt>NameID</dt>
        <dd><code><?=$this->e($nameId->toXml()); ?></code></dd>
<?php endif; ?>

        <dt>AuthnTime</dt>
        <dd><code><?=$this->e($samlAssertion->getAuthnInstant()->format(DateTime::ATOM)); ?></code></dd>

        <dt>SessionNotOnOrAfter</dt>
        <dd><code><?=$this->e($samlAssertion->getSessionNotOnOrAfter()->format(DateTime::ATOM)); ?></code></dd>

        <dt>AuthnContext</dt>
        <dd><code><?=$this->e($samlAssertion->getAuthnContext()); ?></code></dd>
    </dl>

<?php if (0 !== \count($samlAssertion->getAttributes())): ?>
    <h2><?=$this->t('Attributes'); ?></h2>
    <dl>
<?php foreach ($samlAssertion->getAttributes() as $attributeName => $attributeValueList): ?>
        <dt><?=$this->e($attributeName); ?></dt>
        <dd>
            <ul>
<?php foreach ($attributeValueList as $attributeValue): ?>
                <li><code><?=$this->e($attributeValue); ?></code></li>
<?php endforeach; ?>
            </ul>
        </dd>
<?php endforeach; ?>
    </dl>
<?php endif; ?>
    <p>
        <a href="logout?ReturnTo=<?=$logoutReturnTo; ?>"><button><?=$this->t('Logout'); ?></button></a>
    </p>
<?php $this->stop('content'); ?>
