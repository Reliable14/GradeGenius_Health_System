<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

echo json_encode([
    'status' => 'active',
    'components' => [
        'learning_api' => 'active',
        'course_catalog' => 'active',
    ],
], JSON_UNESCAPED_SLASHES);
