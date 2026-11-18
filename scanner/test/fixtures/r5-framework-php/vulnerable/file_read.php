<?php
$name = $_GET['file'];
echo htmlspecialchars(file_get_contents('/srv/docs/' . $name));