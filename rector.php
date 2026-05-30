<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;

return RectorConfig::configure()
    ->withPaths([
        __DIR__ . '/bin/convert',
        __DIR__ . '/data',
        __DIR__ . '/src',
    ])
    ->withImportNames(
        importShortClasses: false,
        removeUnusedImports: true,
    )
    ->withPreparedSets(symfonyCodeQuality: true)
    ->withComposerBased(symfony: true);
