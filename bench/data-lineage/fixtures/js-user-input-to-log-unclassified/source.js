// NOTE: bare `input()` is Python syntax written in a .js file on purpose —
// see this fixture's expected.json `notes`.
function promptForSsn() {
  const ssn = input();
  console.log('collected', ssn);
}
