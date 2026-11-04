function mailRecord(fs, sendMail) {
  const record = fs.readFileSync('/var/records/patient.json');
  sendMail({ body: record });
}
