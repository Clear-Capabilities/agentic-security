# Synthetic fixture: the permission check only runs for exporters that need the secret, but the secret is handed to every exporter.
class ExportView(Resource):
    def post(self, record_id):
        record = store.get(record_id)
        exporter = pick_exporter(request.json)

        if exporter.needs_secret:
            if not record.secret:
                return {"message": "no secret on record"}, 400
            if g.current_user != record.creator:
                perm = RecordPermission(record.owner)
                if not perm.can():
                    return {"message": "forbidden"}, 403

        result = exporter.run(record.body, record.secret)
        return {"data": result}
