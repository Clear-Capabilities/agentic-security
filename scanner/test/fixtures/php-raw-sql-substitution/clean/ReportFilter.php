<?php

class ReportFilter
{
    public function applyRange($query, $template, $low, $high)
    {
        $query->whereRaw($template, ['low' => $low, 'high' => $high]);
    }

    public function applyQuoted($query, $pdo, $template, $low)
    {
        $query->whereRaw(strtr($template, [':low' => $pdo->quote($low)]));
    }

    public function applyName($query, $limit)
    {
        $query->havingRaw(sprintf('total > %d', $limit));
    }

    public function rowsForTags($db, $payload)
    {
        $ids = array_map('intval', json_decode($payload, true));
        $sql = "SELECT * FROM rows WHERE tag_id IN (" . implode(",", $ids) . ")";
        return $db->query($sql);
    }
}
