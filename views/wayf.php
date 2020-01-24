<?php $this->layout('base'); ?>
<?php $this->start('content'); ?>
<h2><?=$this->t('Where are you from?'); ?></h2>
<p>
<?=$this->t('Select your organization from the list below to continue the login process.'); ?>
</p>
<?php if (0 === \count($idpInfoList)): ?>
    <p class="warning">
<?=$this->t('No IdP(s) configured for authenticating to this SP!'); ?>
    </p>
<?php else: ?>
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
