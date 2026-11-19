<?php
$dir = $_GET['dir'];
popen('ls ' . escapeshellarg($dir), 'r');