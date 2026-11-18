class History:
    blocked = ("--output", "-o", "--exec", "--upload-pack")

    def __init__(self, repo, checker):
        self.repo = repo
        self.checker = checker

    def changes(self, rev, **opts):
        self.checker.check_unsafe_options(list(opts), self.blocked)
        return self.repo.git.log(rev, "--oneline", **opts).splitlines()

    def status(self, **opts):
        return self.repo.git.status(**opts)
