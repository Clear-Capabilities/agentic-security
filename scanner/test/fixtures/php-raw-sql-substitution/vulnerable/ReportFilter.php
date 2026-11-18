<?php

class ReportFilter
{
    public function applyRange($query, $template, $low, $high)
    {
        $query->whereRaw(strtr($template, [
            ':low'  => $low,
            ':high' => $high,
        ]));
    }

    public function applyName($query, $name)
    {
        $query->havingRaw(sprintf("label = '%s'", $name));
    }

    public function rowsForTags($db, $payload)
    {
        $sql = "SELECT * FROM rows WHERE tag_id IN (" . implode(",", json_decode($payload, true)) . ")";
        return $db->query($sql);
    }
}
