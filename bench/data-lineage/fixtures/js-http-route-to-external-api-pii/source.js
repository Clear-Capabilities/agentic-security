function syncProfile(req) {
  const ssn = req.params.ssn;
  fetch('https://partner.example/profile?ssn=' + ssn);
}
