// Mitigated: role comes only from a real, separately-verified session; no debug bypass exists.
const role = 'anonymous';
const secret = process.env.GUARDED_RESOURCE_VALUE || '';
if (role === 'admin') console.log(secret);
