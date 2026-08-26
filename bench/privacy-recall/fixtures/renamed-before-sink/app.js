function logUser(req) {
  const socialSecurityNumber = req.body.value;
  const y = socialSecurityNumber;
  console.log(y);
}
module.exports = { logUser };
