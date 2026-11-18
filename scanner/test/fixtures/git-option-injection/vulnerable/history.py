class History:
    def __init__(self, repo):
        self.repo = repo

    def changes(self, rev, **opts):
        return self.repo.git.log(rev, "--oneline", **opts).splitlines()
