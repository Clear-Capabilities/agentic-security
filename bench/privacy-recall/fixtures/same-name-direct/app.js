function logUser(req) {
  const socialSecurityNumber = req.body.value;
  console.log(socialSecurityNumber);
}
module.exports = { logUser };
