<?php
declare(strict_types=1);

$demo = require __DIR__ . '/demo-data.php';
header('Content-Type: application/json; charset=utf-8');
echo json_encode($demo['courses'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
