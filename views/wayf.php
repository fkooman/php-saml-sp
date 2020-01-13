<?php $this->layout('base'); ?>
<?php $this->start('content'); ?>
    <h2>Where are you from?</h2>
<?php if (0 === \count($availableIdpList)): ?>
    <p class="warning">
        No IdPs are currently configured for authenticating to this SP!
    </p>
<?php else: ?>
    <p>
        Select your organization.
    </p>
    <ul>
<?php foreach ($availableIdpList as $entityId): ?>
        <li><a href="login?ReturnTo=<?=$this->e($returnTo); ?>&IdP=<?=$this->e($entityId); ?>"><?=$this->e($entityId); ?></a></li>
<?php endforeach; ?>
    </ul>
<?php endif; ?>
<?php $this->stop('content'); ?>
