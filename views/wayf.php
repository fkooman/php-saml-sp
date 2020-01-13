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
        <li>
            <form method="get" action="login">
                <input type="hidden" name="ReturnTo" value="<?=$this->e($returnTo); ?>">
                <input type="hidden" name="IdP" value="<?=$this->e($entityId); ?>">
                <button type="submit"><?=$this->e($entityId); ?></button>
            </form>
        </li>
<?php endforeach; ?>
    </ul>
<?php endif; ?>
<?php $this->stop('content'); ?>
