function resumeSession(req, res) {
  const sessionToken = req.cookies.session_token;
  res.redirect('/resume?t=' + sessionToken);
}
