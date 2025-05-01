// Imports
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import Stripe from 'stripe';
import admin from 'firebase-admin';
import jwt from 'jsonwebtoken';

dotenv.config();

// Express app
const app = express();
app.use(cors());
app.use(express.json());

// Connect MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/dashboard')
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Firebase Admin setup
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: 'airbubble2-5be80',
      clientEmail: "firebase-adminsdk-fbsvc@airbubble2-5be80.iam.gserviceaccount.com",
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    }),
  });
}

// Stripe setup
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// JWT Auth Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ firebaseUid: decoded.uid });

    if (!user || !user.sessionExpiresAt || new Date() > new Date(user.sessionExpiresAt)) {
      return res.status(401).json({ error: 'Session expired. Please log in again.' });
    }

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Mongoose User Schema
const userSchema = new mongoose.Schema({
  firebaseUid: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  tokenId: { type: String },
  sessionId: { type: String },
  sessionExpiresAt: { type: Date },
  name: String,
  provider: { type: String, enum: ['email', 'google', 'apple'], default: 'email' },
  photoURL: String,
  createdAt: { type: Date, default: Date.now },
  settings: {
    twoFactorEnabled: { type: Boolean, default: false }
  }
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || this.provider !== 'email') return next();
  try {
    this.password = await bcrypt.hash(this.password, 10);
    next();
  } catch (error) {
    next(error);
  }
});

const User = mongoose.model('User', userSchema);

// Home route
app.get('/', (req, res) => {
  console.log('Home route accessed');
  res.send('Welcome to the /route endpoint!');
});

// Helper for setting session expiration (2 hours)
const getSessionExpiration = () => {
  const now = new Date();
  now.setHours(now.getHours() + 2);
  return now;
};

// Signup
app.post('/api/users', async (req, res) => {
  try {
    const { firebaseUid, email, password, tokenId, sessionId, provider = 'email', photoURL, name } = req.body;

    if (!firebaseUid || !email) {
      return res.status(400).json({ error: 'Firebase UID and email are required.' });
    }

    let user = await User.findOne({ firebaseUid });
    if (user) {
      user.tokenId = tokenId || user.tokenId;
      user.sessionId = sessionId || user.sessionId;
      user.sessionExpiresAt = getSessionExpiration();
      await user.save();
      return res.status(200).json({ message: 'User already exists, session updated', user });
    }

    user = new User({
      firebaseUid,
      email,
      password: password || `${provider}-auth-user`,
      tokenId,
      sessionId,
      provider,
      photoURL,
      name,
      sessionExpiresAt: getSessionExpiration()
    });

    await user.save();
    res.status(201).json({ message: 'User created successfully', user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password, tokenId, sessionId, provider, callback } = req.body;

    if (!email || (!provider && !password) || !tokenId || !sessionId) {
      return res.status(400).json({ error: 'Required fields missing.' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (user.provider === 'email' && !provider) {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    }

    user.tokenId = tokenId;
    user.sessionId = sessionId;
    user.sessionExpiresAt = getSessionExpiration();
    await user.save();

    const token = jwt.sign({ uid: user.firebaseUid, email: user.email }, process.env.JWT_SECRET, { expiresIn: '2h' });

    if (callback) {
      return res.redirect(`${callback}?token=${token}`);
    }

    res.json({ message: 'Login successful', token, user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Logout
app.post('/api/users/logout', async (req, res) => {
  try {
    const { firebaseUid } = req.body;

    if (!firebaseUid) {
      return res.status(400).json({ error: 'Firebase UID is required.' });
    }

    const user = await User.findOne({ firebaseUid });
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.sessionId = null;
    user.tokenId = null;
    user.sessionExpiresAt = null;
    await user.save();

    res.json({ message: 'User logged out successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// OAuth login/signup
app.post('/api/users/oauth', async (req, res) => {
  try {
    const { firebaseUid, email, tokenId, sessionId, provider, photoURL, name, callback } = req.body;

    if (!firebaseUid || !email || !provider || !tokenId || !sessionId) {
      return res.status(400).json({ error: 'All fields are required for OAuth.' });
    }

    let user = await User.findOne({ firebaseUid });
    if (user) {
      user.tokenId = tokenId;
      user.sessionId = sessionId;
      user.sessionExpiresAt = getSessionExpiration();
      if (photoURL) user.photoURL = photoURL;
      if (name) user.name = name;
      await user.save();

      const token = jwt.sign({ uid: user.firebaseUid, email: user.email }, process.env.JWT_SECRET, { expiresIn: '2h' });

      if (callback) {
        return res.redirect(`${callback}?token=${token}`);
      }

      return res.json({ message: 'OAuth login successful', token, user });
    }

    user = new User({
      firebaseUid,
      email,
      password: `${provider}-auth-user`,
      tokenId,
      sessionId,
      provider,
      photoURL,
      name,
      sessionExpiresAt: getSessionExpiration()
    });

    await user.save();

    const token = jwt.sign({ uid: user.firebaseUid, email: user.email }, process.env.JWT_SECRET, { expiresIn: '2h' });

    if (callback) {
      return res.redirect(`${callback}?token=${token}`);
    }

    res.status(201).json({ message: 'OAuth user created successfully', token, user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user by Firebase UID
app.get('/api/users/:firebaseUid', async (req, res) => {
  try {
    const user = await User.findOne({ firebaseUid: req.params.firebaseUid });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { password, ...userData } = user.toObject();
    res.json(userData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Firebase user fetch
app.get('/api/firebase-user/:uid', async (req, res) => {
  const { uid } = req.params;
  try {
    const userRecord = await admin.auth().getUser(uid);
    res.json({
      uid: userRecord.uid,
      email: userRecord.email,
      phoneNumber: userRecord.phoneNumber,
      displayName: userRecord.displayName,
      photoURL: userRecord.photoURL,
      providerData: userRecord.providerData,
      emailVerified: userRecord.emailVerified,
      disabled: userRecord.disabled,
      metadata: userRecord.metadata,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Example protected route
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Accessed protected route', user: req.user });
});

// Stripe PaymentIntent
app.post('/api/payment/create', async (req, res) => {
  try {
    const { amount, currency = 'usd' } = req.body;
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency,
      automatic_payment_methods: { enabled: true }
    });
    res.status(200).json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Stripe Customer
app.post('/api/stripe/customer', async (req, res) => {
  try {
    const { email, name } = req.body;
    const customer = await stripe.customers.create({ email, name });
    res.status(200).json({ customerId: customer.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Stripe Checkout Session
app.post('/api/create-checkout-session', async (req, res) => {
  const { priceId } = req.body;
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: 'http://localhost:3000/success',
      cancel_url: 'http://localhost:3000/cancel',
    });
    res.json({ id: session.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
