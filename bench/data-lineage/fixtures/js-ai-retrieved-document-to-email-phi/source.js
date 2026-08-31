function forwardDocument(resource, sendMail) {
  const medicalRecord = resource.contents.medical_record;
  sendMail({ to: 'partner@example.com', body: medicalRecord });
}
