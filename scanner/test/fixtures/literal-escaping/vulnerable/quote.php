<?php
function js_string($value) {
    return "'" . str_replace("'", "\\'", $value) . "'";
}
