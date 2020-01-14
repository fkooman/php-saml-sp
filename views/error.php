<?php $this->layout('base'); ?>
<?php $this->start('content'); ?>
    <h2><?=$this->t('Error'); ?></h2>
    <h3><?=$this->e($e->getCode()); ?> - <?=$this->e($e->getHttpError()); ?></h3>
<?php if ('' !== $e->getMessage()): ?>
    <dl>
        <dt><?=$this->t('Error Message'); ?></dt>
        <dd><code><?=$this->e($e->getMessage()); ?></code></dd>
    </dl>
<?php endif; ?>
<?php $this->stop('content'); ?>
