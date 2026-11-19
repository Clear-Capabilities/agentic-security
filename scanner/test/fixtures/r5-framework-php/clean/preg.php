<?php
$pattern = '/' . preg_quote($_GET['pattern'], '/') . '/';
preg_match($pattern, 'some text');