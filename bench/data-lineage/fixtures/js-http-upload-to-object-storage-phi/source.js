// NOTE: `request.FILES` is Django (Python) syntax written in a .js file on
// purpose — it mirrors the ONLY catalog entry that reaches the `http-upload`
// source category (`py-django-request-FILES`), following the same precedent
// scanner/test/lineage/registry-real-code.test.js established for the four
// source categories with no `language: 'js'` representative. See this
// fixture's expected.json `notes` for why it is capability-tier.
function uploadChart(request, s3) {
  const medicalRecord = request.FILES.medical_record;
  s3.putObject('patient-charts/latest.json', medicalRecord);
}
