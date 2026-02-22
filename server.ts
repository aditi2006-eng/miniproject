import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { createServer as createViteServer } from 'vite';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import Razorpay from 'razorpay';
import db from './src/db.ts';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer);
const PORT = 3000;

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || 'rzp_test_dummy';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || 'dummy_secret';

const razorpay = new Razorpay({
  key_id: RAZORPAY_KEY_ID,
  key_secret: RAZORPAY_KEY_SECRET,
});

// Email Transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: parseInt(process.env.EMAIL_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Helper: Send Email
async function sendEmail(to: string, subject: string, text: string) {
  try {
    if (!process.env.EMAIL_USER) {
      console.log('Email not configured. Skipping email to:', to);
      console.log('Subject:', subject);
      console.log('Text:', text);
      return;
    }
    await transporter.sendMail({
      from: `"SliceMaster" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      text,
    });
  } catch (error) {
    console.error('Error sending email:', error);
  }
}

// Socket.io Connection
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  socket.on('join', (userId) => {
    socket.join(`user_${userId}`);
  });
});

// --- Auth Routes ---

app.post('/api/auth/register', async (req, res) => {
  const { email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const stmt = db.prepare('INSERT INTO users (email, password, role, is_verified) VALUES (?, ?, ?, 1)');
    stmt.run(email, hashedPassword, role || 'user');
    
    res.json({ message: 'Registration successful. You can now login.' });
  } catch (error: any) {
    res.status(400).json({ error: 'Email already exists' });
  }
});

app.post('/api/auth/quick-login', async (req, res) => {
  const { email } = req.body;
  let user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as any;

  if (!user) {
    // Auto-register new user
    const stmt = db.prepare('INSERT INTO users (email, role, is_verified) VALUES (?, ?, 1)');
    const result = stmt.run(email, 'user');
    user = { id: result.lastInsertRowid, email, role: 'user' };
  }

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET);
  res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as any;

  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET);
    res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  const resetToken = Math.random().toString(36).substring(2, 15);
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as any;

  if (user) {
    db.prepare('UPDATE users SET reset_token = ? WHERE id = ?').run(resetToken, user.id);
    await sendEmail(email, 'Password Reset', `Your reset token is: ${resetToken}`);
  }
  res.json({ message: 'If email exists, reset link has been sent.' });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND reset_token = ?').get(email, token) as any;

  if (user) {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.prepare('UPDATE users SET password = ?, reset_token = NULL WHERE id = ?').run(hashedPassword, user.id);
    res.json({ message: 'Password reset successful' });
  } else {
    res.status(400).json({ error: 'Invalid token or email' });
  }
});

// --- Inventory Routes ---

app.get('/api/inventory', (req, res) => {
  const items = db.prepare('SELECT * FROM inventory').all();
  res.json(items);
});

app.put('/api/inventory/:id', (req, res) => {
  const { id } = req.params;
  const { stock } = req.body;
  db.prepare('UPDATE inventory SET stock = ? WHERE id = ?').run(stock, id);
  res.json({ message: 'Stock updated' });
});

// --- Order Routes ---

app.post('/api/orders/create-payment', async (req, res) => {
  const { amount } = req.body;
  try {
    // Attempt real Razorpay order creation
    const order = await razorpay.orders.create({
      amount: amount * 100, // amount in paisa
      currency: 'INR',
      receipt: `receipt_${Date.now()}`,
    });
    res.json(order);
  } catch (error) {
    console.warn('Razorpay order creation failed, falling back to mock order for testing.');
    // Return a mock order object so the frontend can still proceed in "test mode"
    res.json({
      id: `order_mock_${Date.now()}`,
      amount: amount * 100,
      currency: 'INR',
      isMock: true
    });
  }
});

app.post('/api/orders', async (req, res) => {
  const { userId, items, total, paymentId, address } = req.body;
  
  try {
    // Start transaction
    const transaction = db.transaction(() => {
      // Create order
      const stmt = db.prepare('INSERT INTO orders (user_id, items, total, payment_id, address) VALUES (?, ?, ?, ?, ?)');
      const result = stmt.run(userId, JSON.stringify(items), total, paymentId, address);
      const orderId = result.lastInsertRowid;

      // Update inventory
      const parsedItems = items; // Expecting { category: name } or similar
      for (const category in parsedItems) {
        const itemName = parsedItems[category];
        if (Array.isArray(itemName)) {
          for (const name of itemName) {
            db.prepare('UPDATE inventory SET stock = stock - 1 WHERE name = ?').run(name);
          }
        } else {
          db.prepare('UPDATE inventory SET stock = stock - 1 WHERE name = ?').run(itemName);
        }
      }

      // Check thresholds and notify admin
      const lowStockItems = db.prepare('SELECT * FROM inventory WHERE stock < threshold').all() as any[];
      if (lowStockItems.length > 0) {
        const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
        const itemNames = lowStockItems.map(i => `${i.name} (${i.stock} left)`).join(', ');
        sendEmail(adminEmail, 'Low Stock Alert', `The following items are below threshold: ${itemNames}`);
      }

      return orderId;
    });

    const orderId = transaction();
    res.json({ id: orderId, message: 'Order placed successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error placing order' });
  }
});

app.get('/api/orders/user/:userId', (req, res) => {
  const orders = db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC').all(req.params.userId);
  res.json(orders);
});

app.get('/api/orders', (req, res) => {
  const orders = db.prepare('SELECT orders.*, users.email FROM orders JOIN users ON orders.user_id = users.id ORDER BY created_at DESC').all();
  res.json(orders);
});

app.put('/api/orders/:id/status', (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, id);
  
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(id) as any;
  if (order) {
    io.to(`user_${order.user_id}`).emit('order_status_update', { orderId: id, status });
  }
  
  res.json({ message: 'Status updated' });
});

// --- Vite Integration ---

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
