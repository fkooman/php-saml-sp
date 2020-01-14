<?php $this->layout('base'); ?>
<?php $this->start('content'); ?>
    <h2>Assertion</h2>
    <table class="tbl">
        <tbody>
        <tr>
            <th>Issuer</th><td><?=$this->e($samlAssertion->getIssuer()); ?></td>
        </tr>
<?php if (null !== $nameId = $samlAssertion->getNameId()): ?>
        <tr>
            <th>NameID</th><td><?=$this->e($nameId->toXml()); ?></td>
        </tr>
<?php endif; ?>
        <tr>
            <th>AuthnTime</th><td><?=$this->e($samlAssertion->getAuthnInstant()->format(DateTime::ATOM)); ?></td>
        </tr>
        <tr>
            <th>AuthnContext</th><td><?=$this->e($samlAssertion->getAuthnContext()); ?></td>
        </tr>
        </tbody>
    </table>

<?php if (0 !== \count($samlAssertion->getAttributes())): ?>
    <h3>Attributes</h3>
    <table class="tbl">
        <tbody>
<?php foreach ($samlAssertion->getAttributes() as $attributeName => $attributeValueList): ?>
        <tr>
            <th><?=$this->e($attributeName); ?></th>
            <td>
                <ul>
<?php foreach ($attributeValueList as $attributeValue): ?>
                    <li><?=$this->e($attributeValue); ?></li>
<?php endforeach; ?>
                </ul>
            </td>
        </tr>
<?php endforeach; ?>
        </tbody>
    </table>
<?php endif; ?>
    <p>
        <a href="logout?ReturnTo=<?=$returnTo; ?>"><button>Logout</button></a>
    </p>
<?php $this->stop('content'); ?>
