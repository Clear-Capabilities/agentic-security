<?php
$city = $_GET['city'];
header('Content-Type: application/json');
echo json_encode(['city' => $city]);
