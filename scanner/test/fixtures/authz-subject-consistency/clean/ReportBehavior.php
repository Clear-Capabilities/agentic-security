<?php
// Synthetic fixture: every handler of an action runs the action's check.
class ReportBehavior
{
    public function publish()
    {
        if (!$this->userHasAccess('publish')) {
            abort(403);
        }
        return $this->render('publish');
    }

    public function archive()
    {
        if (!$this->userHasAccess('archive')) {
            abort(403);
        }
        return $this->render('archive');
    }

    public function onPublish()
    {
        if (!$this->userHasAccess('publish')) {
            abort(403);
        }
        $report = $this->loadReport(post('id'));
        $report->publish();
        return ['ok' => true];
    }

    public function onArchiveConfirm()
    {
        if (!$this->userHasAccess('archive')) {
            abort(403);
        }
        $this->loadReport(post('id'))->archive();
    }

    public function userHasAccess(string $type): bool
    {
        return $this->user->hasPermission('reports.' . $type);
    }
}
