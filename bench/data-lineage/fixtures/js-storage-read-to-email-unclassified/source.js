// NOTE: bare `open(...)` is Python syntax written in a .js file on purpose
// — see this fixture's expected.json `notes`.
function mailRecord(sendMail) {
  const record = open('/var/records/patient.json');
  sendMail({ body: record });
}
