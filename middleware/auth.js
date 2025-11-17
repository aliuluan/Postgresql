const pool = require('../database/db');

function requirePermission(ressource, action) {
    // Retourne la fonction middleware réelle
    return async function (req, res, next) {
        try {
            const userId = req.user.id;
            const result = await pool.query(
                `SELECT utilisateur_a_permission($1, $2, $3) AS has_permission`,
                [userId, ressource, action]
            );

            if (!result.rows[0].has_permission) {
                return res.status(403).json({ error: 'Permission refusée' });
            }

            next();
        } catch (err) {
            console.error('Erreur middleware permission:', err);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    };
}

async function requireAuth(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Token manquant' });

    try {
        const result = await pool.query(
            `SELECT s.utilisateur_id AS id, u.email, u.nom, u.prenom
       FROM sessions s
       INNER JOIN utilisateurs u ON s.utilisateur_id = u.id
       WHERE s.token = $1 AND s.actif = true AND s.date_expiration > NOW() AND u.actif = true`,
            [token]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Token invalide ou expiré' });
        }

        req.user = result.rows[0];
        next();
    } catch (error) {
        console.error('Erreur middleware auth:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
}

module.exports = { requireAuth, requirePermission };
