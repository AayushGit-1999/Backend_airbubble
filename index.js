// Imports
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import Stripe from 'stripe';
import admin from 'firebase-admin';

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
      privateKey: "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDtsrS6/Hp9hLvA\nVdWS8WdHmykn1TsdV/Q8lMJiAtJvVzstU6R/udXCkZ53rQNzNSpUahiYF29b1GG5\nHhiI7jcqaQkBJ7tMMVgdf/FvHgDZtXgdanwwnMKKeVEawn/6RFR+5uTI4A1Hfjvi\noyOOerzWYaHMOLSdajNHxgIeeJZ0Hh8llxqgHtgCTbYUoM1pqyWZpE3f8VfjBxdM\nK1cME4ZU//cuLRje0zOXONmS4HFGtmMIl6+YnQCIroTWXiqj1pCkiBKr6ZRPDorE\nyQWkZmbg9KSfXrdmzZjwrsPC8pQ57/EUJBbsYZ/r8RBNmVzaO8bra6zG583rTEu8\nd6ZZqjANAgMBAAECggEACygzuSvSWLjrEnyU6/Lz0kBzXpYbfRBHUQlPKcg7IL8b\nR9CLbJ6y7Lvmux7+W0vYDaKgk+b/CEmVlVmsdM+a/EfLhJKHr+xdrUjM8tZu23Pb\n9vmBactkiu5l2Fff0kX0d15sHQz94pNcyTxiFgp8eaLsiXLx8LTu7O6w48WXk6H3\nz6ZLF0Mq+Q0bPkyCAuGRGR4UNjcFY0uX86WPj7yrd4XA1Cry82w5Rct77S3UkAFJ\ndrJHY9MI01co6WoULFsCrej5D2Y8CY4+jsExKHxtYIN8vP3A4IXGRhA0qiopOOh3\nq8sbiOJkyjIkCDylSwqMAqC8TE2pZ9shsOCbzUjYewKBgQD/48LTMUIJUhDk+dGj\nQ6E2LfjaCLI2nJoIaSp7We1m3LxLUUlIJzzT0VWlTk90KfqCD+rafXXsL8ePv9aZ\nkvCtZ4Ku8QQ9loDgPH+g+XrrfmXAiJqb4skbvMgAN5ToqUbrKDC75ZSjXqn2YJBy\n7WJ6ho9252Kfm6vAuwqNKnsAJwKBgQDtzO/4sCCgWBm6j1MgYSH5S2vC7md0orug\nHTqYijm33z7GEet5v6GiXJefH4olAJ4vgVEaOdbs+wRQLjThPZJ0zCzhUgN4RrZL\nyTSjEXRHsjYhF2CEdiKFWBcVA56+ffKVW7FHajo2d0IBfz0FafvtfobxgRiaOADW\nynnJ1636qwKBgQCyXZ6F+8XeHVgtY32fYhrTW0QlJv6iVpJ/3l6AUPTMSHzvux9r\nrf4WX8plSarUfBZj5ph76Av0sHFYYA5ESkp9dLOBIfskuu3mYAVOvdfSou5mQFIU\n6wXn0bVPgW7IpoYKkJ83uhXbsraiSDkoAxQr9/O0nCEAxE/6LeZy8/N87QKBgQDF\n1hjTIdyS6ZjGH9U9e/Hiz/9gFi1V2MkVxRtpqp2oPn+gE2p/SJF1XWj7BidM732q\n8gACPJp1X8RP3JE7zpjYuMCh2DRwzQt+c29qNuwxda8YyrUOnqXLn+TcI73epzO5\nVKZhTpwNkhwE2NFwfqMMC5bCtu875lm0WJEH/nqMrwKBgQClilLjo+KD6x6rZeCk\n40se8qpF9ksf8doI7pFYzSHOZjwBhm7+H5t1MU0Xl0NZ56eL7ujb5D4Nr3ct5OXG\nKbaz99x3Qfqem/mhlOYQZshFcYOoYPXZmcJ2AD3k1LjOQgqwQJTu+in4xXE4JCa6\nK20jke46MNh9sI2Xn+u3y3YDfA==\n-----END PRIVATE KEY-----\n",
    }),
  });
}

// Stripe setup
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Mongoose User Schema
const userSchema = new mongoose.Schema({
  firebaseUid: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  tokenId: { type: String },
  sessionId: { type: String },
  name: String,
  provider: { type: String, enum: ['email', 'google', 'apple'], default: 'email' },
  photoURL: String,
  createdAt: { type: Date, default: Date.now },
  settings: {
    twoFactorEnabled: { type: Boolean, default: false }
  }
});

// Hash password before saving
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

// Routes

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
      name
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
    const { email, password, tokenId, sessionId, provider } = req.body;

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
    await user.save();

    res.json({ message: 'Login successful', user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// OAuth Login/Signup
app.post('/api/users/oauth', async (req, res) => {
  try {
    const { firebaseUid, email, tokenId, sessionId, provider, photoURL, name } = req.body;

    if (!firebaseUid || !email || !provider || !tokenId || !sessionId) {
      return res.status(400).json({ error: 'All fields are required for OAuth.' });
    }

    let user = await User.findOne({ firebaseUid });
    if (user) {
      user.tokenId = tokenId;
      user.sessionId = sessionId;
      if (photoURL) user.photoURL = photoURL;
      if (name) user.name = name;
      await user.save();
      return res.json({ message: 'OAuth login successful', user });
    }

    user = new User({
      firebaseUid,
      email,
      password: `${provider}-auth-user`,
      tokenId,
      sessionId,
      provider,
      photoURL,
      name
    });

    await user.save();
    res.status(201).json({ message: 'OAuth user created successfully', user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get User by Firebase UID
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

// Create new User (Duplicate API)
app.post('/api/usersss', async (req, res) => {
  try {
    const { firebaseUid, email, password, tokenId, sessionId, name, provider, photoURL, settings } = req.body;

    const newUser = new User({ firebaseUid, email, password, tokenId, sessionId, name, provider, photoURL, settings });
    await newUser.save();

    res.status(201).json({ message: 'User created successfully', user: newUser });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Get Firebase Auth User
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
    console.error('Error fetching Firebase user:', error);
    res.status(500).json({ error: error.message });
  }
});


// STRIPE INTEGRATION 🚀🚀

// Create PaymentIntent
app.post('/api/payment/create', async (req, res) => {
  try {
    const { amount, currency = 'usd' } = req.body;

    const paymentIntent = await stripe.paymentIntents.create({
      amount,  // e.g., 500 for $5.00
      currency,
      automatic_payment_methods: { enabled: true }
    });

    res.status(200).json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    console.error('Stripe PaymentIntent Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Create Stripe Customer (optional)
app.post('/api/stripe/customer', async (req, res) => {
  try {
    const { email, name } = req.body;

    const customer = await stripe.customers.create({
      email,
      name
    });

    res.status(200).json({ customerId: customer.id });
  } catch (error) {
    console.error('Stripe Customer Error:', error);
    res.status(500).json({ error: error.message });
  }
});


// Create Stripe Checkout Session
app.post('/api/create-checkout-session', async (req, res) => {
  const { priceId } = req.body;
  
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [
        {
          price: priceId, // this must match the price ID from your Stripe dashboard
          quantity: 1,
        },
      ],
      success_url: 'http://localhost:3000/success', // where to redirect after successful payment
      cancel_url: 'http://localhost:3000/cancel',    // where to redirect if payment is cancelled
    });

    res.json({ id: session.id });
  } catch (error) {
    console.error('Error creating checkout session:', error);
    res.status(500).json({ error: error.message });
  }
});


// Add this route AFTER your Stripe PaymentIntent and Customer routes
app.post('/api/create-checkout-session', async (req, res) => {
  const { priceId } = req.body;
  
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      success_url: 'http://localhost:3000/success',
      cancel_url: 'http://localhost:3000/cancel',
    });

    res.json({ id: session.id });
  } catch (error) {
    console.error('Error creating checkout session:', error);
    res.status(500).json({ error: error.message });
  }
});




// Server listen
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
