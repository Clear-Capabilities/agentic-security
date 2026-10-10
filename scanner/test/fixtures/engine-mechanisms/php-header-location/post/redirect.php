<?php
$next = $_GET["next"];
if (strpos($next, "/") !== 0 || strpos($next, "//") === 0) {
  $next = "/";
}
header("Location: " . "/app" . $next);
exit;
