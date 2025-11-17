const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const { requireAuth } = require('../middleware/auth');

/* ========================
   POST /api/auth/register
======================== */
router.post('/register', async (req, res) => {
    const { email, password, nom, prenom } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email et mot de passe requis' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Vérifier si email existe
        const checkUser = await client.query(
            'SELECT id FROM utilisateurs WHERE email = $1',
            [email]
        );
        if (checkUser.rows.length > 0) {
            return res.status(400).json({ error: 'Email déjà utilisé' });
        }

        // Hasher le mot de passe
        const passwordHash = await bcrypt.hash(password, 10);

        // Insérer l'utilisateur
        const result = await client.query(
            `INSERT INTO utilisateurs (email, password_hash, nom, prenom)
       VALUES ($1, $2, $3, $4)
       RETURNING id, email, nom, prenom, date_creation`,
            [email, passwordHash, nom, prenom]
        );
        const newUser = result.rows[0];

        // Assigner le rôle "user" par défaut
        await client.query(
            `INSERT INTO utilisateur_roles (utilisateur_id, role_id, date_assignation)
       VALUES ($1, (SELECT id FROM roles WHERE nom = 'user'), NOW())`,
            [newUser.id]
        );

        await client.query('COMMIT');

        res.status(201).json({ message: 'Utilisateur créé avec succès', user: newUser });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erreur création utilisateur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    } finally {
        client.release();
    }
});

/* ========================
   POST /api/auth/login
======================== */
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // Récupérer l'utilisateur
        const userResult = await client.query(
            'SELECT * FROM utilisateurs WHERE email = $1',
            [email]
        );
        if (userResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }
        const user = userResult.rows[0];

        if (!user.actif) {
            await client.query('ROLLBACK');
            return res.status(403).json({ error: 'Utilisateur inactif' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            await client.query('ROLLBACK');
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        // Générer token
        const token = uuidv4();
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 24);

        // Créer session
        await client.query(
            `INSERT INTO sessions (utilisateur_id, token, date_creation, date_expiration, actif)
       VALUES ($1, $2, NOW(), $3, TRUE)`,
            [user.id, token, expiresAt]
        );

        // Logger succès
        await client.query(
            `INSERT INTO logs_connexion (utilisateur_id, email_tentative, succes, message, adresse_ip, user_agent)
       VALUES ($1, $2, TRUE, 'Connexion réussie', $3, $4)`,
            [user.id, user.email, req.ip, req.headers['user-agent']]
        );

        await client.query('COMMIT');

        res.json({
            message: 'Connexion réussie',
            token,
            user: {
                id: user.id,
                email: user.email,
                nom: user.nom,
                prenom: user.prenom
            },
            expiresAt
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erreur login:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    } finally {
        client.release();
    }
});

/* ========================
   POST /api/auth/logout
======================== */
router.post('/logout', requireAuth, async (req, res) => {
    const token = req.headers['authorization'];
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const sessionResult = await client.query(
            `UPDATE sessions SET actif = FALSE
       WHERE token = $1
       RETURNING utilisateur_id`,
            [token]
        );

        if (sessionResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Session introuvable' });
        }

        const utilisateur_id = sessionResult.rows[0].utilisateur_id;

        // Logger la déconnexion
        await client.query(
            `INSERT INTO logs_connexion (utilisateur_id, email_tentative, succes, message, adresse_ip, user_agent)
       VALUES ($1, (SELECT email FROM utilisateurs WHERE id = $1), TRUE, 'Déconnexion', $2, $3)`,
            [utilisateur_id, req.ip, req.headers['user-agent']]
        );

        await client.query('COMMIT');

        res.json({ message: 'Déconnexion réussie' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erreur logout:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    } finally {
        client.release();
    }
});

/* ========================
   GET /api/auth/profile
======================== */
router.get('/profile', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT u.id, u.email, u.nom, u.prenom, u.actif,
              array_agg(r.nom ORDER BY r.nom) AS roles
       FROM utilisateurs u
       LEFT JOIN utilisateur_roles ur ON ur.utilisateur_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
       WHERE u.id = $1
       GROUP BY u.id, u.email, u.nom, u.prenom, u.actif`,
            [req.user.id]
        );

        res.json({ user: result.rows[0] });
    } catch (error) {
        console.error('Erreur profil:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

/* ========================
   GET /api/auth/logs
======================== */
router.get('/logs', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, email_tentative, succes, message, adresse_ip, user_agent, date_heure
       FROM logs_connexion
       WHERE utilisateur_id = $1
       ORDER BY date_heure DESC
       LIMIT 50`,
            [req.user.id]
        );

        res.json({ logs: result.rows });
    } catch (error) {
        console.error('Erreur logs:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

module.exports = router;
