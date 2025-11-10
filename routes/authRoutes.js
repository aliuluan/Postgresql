const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const bcrypt = require('bcrypt');

router.post('/register', async (req, res) => {
  const { email, password, nom, prenom } = req.body;

  // 1. Validation
  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe sont obligatoires' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 2. Vérifier si email existe
    const checkUser = await client.query(
      'SELECT id FROM utilisateurs WHERE email = $1',
      [email]
    );
    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: 'Cet email est déjà utilisé' });
    }

    // 3. Hasher le mot de passe
    const passwordHash = await bcrypt.hash(password, 10);

    // 4. Insérer l'utilisateur
    const result = await client.query(
      `INSERT INTO utilisateurs (email, password_hash, nom, prenom)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, nom, prenom, date_creation`,
      [email, passwordHash, nom || null, prenom || null]
    );
    const newUser = result.rows[0];

    // 5. Assigner le rôle "user"
    await client.query(
      `INSERT INTO utilisateur_roles (utilisateur_id, role_id, date_assignation)
       VALUES ($1, (SELECT id FROM roles WHERE nom = 'user'), NOW())`,
      [newUser.id]
    );

    await client.query('COMMIT');

    res.status(201).json({
      message: 'Utilisateur créé avec succès',
      user: newUser
    });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erreur création utilisateur:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  } finally {
    client.release();
  }
});

module.exports = router;
