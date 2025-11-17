const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const { requireAuth, requirePermission } = require('../middleware/auth');

// GET /api/users?page=1&limit=10 → liste utilisateurs (Task 19)
router.get('/', requireAuth, requirePermission('users', 'read'), async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    try {
        const countResult = await pool.query('SELECT COUNT(*) FROM utilisateurs');
        const totalUsers = parseInt(countResult.rows[0].count, 10);

        const usersResult = await pool.query(
            `SELECT u.id, u.email, u.nom, u.prenom, u.actif,
              array_agg(r.nom ORDER BY r.nom) AS roles
       FROM utilisateurs u
       LEFT JOIN utilisateur_roles ur ON ur.utilisateur_id = u.id
       LEFT JOIN roles r ON r.id = ur.role_id
       GROUP BY u.id
       ORDER BY u.id
       LIMIT $1 OFFSET $2`,
            [limit, offset]
        );

        res.json({
            users: usersResult.rows,
            pagination: {
                page,
                limit,
                total: totalUsers,
                totalPages: Math.ceil(totalUsers / limit)
            }
        });
    } catch (error) {
        console.error('Erreur liste utilisateurs:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// PUT /api/users/:id → modifier utilisateur (Task 20)
router.put('/:id', requireAuth, requirePermission('users', 'write'), async (req, res) => {
    const { id } = req.params;
    const { nom, prenom, actif } = req.body;

    try {
        const result = await pool.query(
            `UPDATE utilisateurs
       SET nom = $1, prenom = $2, actif = $3, date_modification = NOW()
       WHERE id = $4
       RETURNING id, email, nom, prenom, actif, date_modification`,
            [nom, prenom, actif, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Utilisateur non trouvé' });
        }

        res.json({ message: 'Utilisateur mis à jour', user: result.rows[0] });
    } catch (error) {
        console.error('Erreur mise à jour utilisateur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// DELETE /api/users/:id → supprimer utilisateur (Task 21)
router.delete('/:id', requireAuth, requirePermission('users', 'delete'), async (req, res) => {
    const { id } = req.params;

    if (parseInt(id) === req.user.id) {
        return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte' });
    }

    try {
        const result = await pool.query(
            `DELETE FROM utilisateurs WHERE id = $1 RETURNING id, email, nom, prenom`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Utilisateur non trouvé' });
        }

        res.json({ message: 'Utilisateur supprimé', user: result.rows[0] });
    } catch (error) {
        console.error('Erreur suppression utilisateur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// GET /api/users/:id/permissions → permissions d'un utilisateur (Task 22)
router.get('/:id/permissions', requireAuth, async (req, res) => {
    const { id } = req.params;

    try {
        const result = await pool.query(
            `SELECT DISTINCT p.nom, p.ressource, p.action, p.description
       FROM utilisateurs u
       INNER JOIN utilisateur_roles ur ON ur.utilisateur_id = u.id
       INNER JOIN roles r ON r.id = ur.role_id
       INNER JOIN role_permissions rp ON rp.role_id = r.id
       INNER JOIN permissions p ON p.id = rp.permission_id
       WHERE u.id = $1
       ORDER BY p.ressource, p.action`,
            [id]
        );

        res.json({ utilisateur_id: parseInt(id), permissions: result.rows });
    } catch (error) {
        console.error('Erreur récupération permissions:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

module.exports = router;
