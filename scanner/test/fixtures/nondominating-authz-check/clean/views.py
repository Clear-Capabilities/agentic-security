# Synthetic fixture: the secret is read only on the branch that ran the permission check.
class ExportView(Resource):
    def post(self, record_id):
        record = store.get(record_id)
        exporter = pick_exporter(request.json)

        secret = None
        if exporter.needs_secret:
            if not record.secret:
                return {"message": "no secret on record"}, 400
            if g.current_user != record.creator:
                perm = RecordPermission(record.owner)
                if not perm.can():
                    return {"message": "forbidden"}, 403
            secret = record.secret

        result = exporter.run(record.body, secret)
        return {"data": result}
