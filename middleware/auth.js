const pool = require('../database/db');

async function requireAuthWithFunction(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ error: 'Token manquant' });
    }

    try {
        // 1. Vérifier la validité du token via la fonction stockée
        const validResult = await pool.query(
            'SELECT est_token_valide($1) AS valide',
            [token]
        );

        if (!validResult.rows[0].valide) {
            return res.status(401).json({ error: 'Token invalide ou expiré' });
        }

        // 2. Récupérer les informations de l'utilisateur
        const userResult = await pool.query(
            `SELECT s.utilisateur_id AS id, u.email, u.nom, u.prenom
       FROM sessions s
       INNER JOIN utilisateurs u ON s.utilisateur_id = u.id
       WHERE s.token = $1`,
            [token]
        );

        req.user = userResult.rows[0];
        next();

    } catch (error) {
        console.error('Erreur middleware auth:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
}

module.exports = { requireAuthWithFunction };
