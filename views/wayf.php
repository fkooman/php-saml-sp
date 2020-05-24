<?php $this->layout('base'); ?>
<?php $this->start('content'); ?>
<p>
<?=$this->t('Select your organization to continue the login process.'); ?>
</p>
<?php if (0 === \count($idpInfoList)): ?>
    <p class="warning">
<?=$this->t('No IdP(s) configured for authenticating to this SP!'); ?>
    </p>
<?php else: ?>
<?php if (null !== $lastChosenIdpInfo): ?>
    <form method="post">
        <ul>
            <li>
                <button autofocus="autofocus" name="IdP" type="submit" value="<?=$this->e($lastChosenIdpInfo->getEntityId()); ?>"><?=$this->e($lastChosenIdpInfo->getDisplayName()); ?></button>
            </li>
        </ul>
    </form>
    <details>
        <summary><?=$this->t('Other...'); ?></summary>
            <form id="searchBox">
                <input type="text" name="searchFor" placeholder="<?=$this->t('Search for your organization...'); ?>">
            </form>
            <form id="organizationList" method="post">
                <ul>
<?php foreach ($idpInfoList as $idpInfo): ?>
                    <li>
                        <button name="IdP" type="submit" value="<?=$this->e($idpInfo->getEntityId()); ?>"><?=$this->e($idpInfo->getDisplayName()); ?></button>
                    </li>
<?php endforeach; ?>
                </ul>
            </form>
            <span id="noResults"><?=$this->t('No Results!'); ?></span>
    </details>
<?php else: ?>

    <form id="searchBox">
        <input type="text" name="searchFor" placeholder="<?=$this->t('Search for your organization...'); ?>">
    </form>
    <form id="organizationList" method="post">
        <ul>
<?php foreach ($idpInfoList as $idpInfo): ?>
            <li>
                <button name="IdP" type="submit" value="<?=$this->e($idpInfo->getEntityId()); ?>"><?=$this->e($idpInfo->getDisplayName()); ?></button>
            </li>
<?php endforeach; ?>
        </ul>
    </form>
    <span id="noResults"><?=$this->t('No Results!'); ?></span>
<?php endif; ?>
<?php endif; ?>
<?php $this->stop('content'); ?>
