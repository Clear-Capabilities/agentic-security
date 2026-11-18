<?php
// Synthetic fixture: a behavior whose pages check the action by name and whose AJAX handlers for the same action do not.
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
