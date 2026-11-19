<?php
$dir = $_GET['dir'];
popen('ls ' . $dir, 'r');