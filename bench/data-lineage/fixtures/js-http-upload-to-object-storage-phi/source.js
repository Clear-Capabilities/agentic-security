function uploadChart(req, s3) {
  const medicalRecord = req.files.medical_record;
  s3.putObject('patient-charts/latest.json', medicalRecord);
}
