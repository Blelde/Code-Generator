const bcrypt = require('bcrypt');
const { createUser, findUserByEmail, updateUserSubscription } = require('./database');

app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  const existingUser = await findUserByEmail(email);
  if (existingUser) {
    return res.status(409).send({ error: 'Email already registered' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await createUser(email, hashedPassword);

  req.session.userId = user._id;
  res.send({ success: true });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await findUserByEmail(email);
  if (!user) {
    return res.status(401).send({ error: 'Invalid email or password' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).send({ error: 'Invalid email or password' });
  }

  req.session.userId = user._id;
  res.send({ success: true });
});

app.post('/change-subscription', async (req, res) => {
  const { subscription } = req.body;
  const { userId } = req.session;

  if (!userId) {
    return res.status(401).send({ error: 'Unauthorized' });
  }

  await updateUserSubscription(userId, subscription);
  res.send({ success: true });
});
