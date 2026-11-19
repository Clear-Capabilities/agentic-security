<?php
$title = htmlentities($_POST['title'], ENT_QUOTES, 'UTF-8');
print("<h2>" . $title . "</h2>");
