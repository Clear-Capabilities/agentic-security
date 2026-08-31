function archiveToolCall(params, s3) {
  const patientRecord = params.arguments.patient_record;
  s3.putObject('tool-calls/latest.json', patientRecord);
}
