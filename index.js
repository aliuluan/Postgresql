const express = require('express');
const pool = require('./database/db');
const authRoutes = require('./routes/authRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);

// Health check
app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.status(200).json({
      status: 'ok',
      server_time: result.rows[0].now,
    });
  } catch (err) {
    console.error('❌ Health check error:', err);
    res.status(500).json({ status: 'error', message: 'Impossible de se connecter à la base de données' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
});