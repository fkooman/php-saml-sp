<?php $this->layout('base'); ?>
<?php $this->start('content'); ?>
    <h2>Where are you from?</h2>
<?php if (0 === \count($idpInfoList)): ?>
    <p class="warning">
        No IdPs are currently configured for authenticating to this SP!
    </p>
<?php else: ?>
    <p>
        Select your organization.
    </p>
    <form method="get" action="wayf">
        <input type="hidden" name="ReturnTo" value="<?=$this->e($returnTo); ?>">
        <ul>
<?php foreach ($idpInfoList as $idpInfo): ?>
            <li>
                <button name="IdP" type="submit" value="<?=$this->e($idpInfo->getEntityId()); ?>"><?=$this->e($idpInfo->getDisplayName()); ?></button>
            </li>
<?php endforeach; ?>
        </ul>
    </form>
<?php endif; ?>
<?php $this->stop('content'); ?>
