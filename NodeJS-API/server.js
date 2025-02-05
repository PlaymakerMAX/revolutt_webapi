require('dotenv').config(); // Charge les variables d'environnement depuis le fichier .env
const express = require('express'); // Pour gérer les routes
const bodyParser = require('body-parser'); // Pour parser le corps des requêtes
const cors = require('cors'); // Pour activer CORS
const crypto = require('crypto'); // Pour les opérations de chiffrement/déchiffrement
const jwt = require('jsonwebtoken'); // Pour générer et vérifier des tokens JWT
const bcrypt = require('bcrypt'); // Pour comparer les mots de passe hachés
const db = require('./database'); // Module de connexion à la base de données

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Clé secrète pour le JWT (à définir dans le fichier .env)
const JWT_SECRET = process.env.JWT_SECRET || 'votre_clé_secrète';

/* ============================================================
   Fonctions de chiffrement / déchiffrement du solde
   ============================================================ */

/**
 * Déchiffre le solde chiffré d'un compte.
 * @param {Buffer|string} encryptedSolde - Le solde chiffré stocké dans la base.
 * @param {string} secretKey - La clé secrète associée au compte.
 * @returns {number|null} - Le solde en clair ou null en cas d'erreur.
 */
function decryptSolde(encryptedSolde, secretKey) {
  try {
    const decipher = crypto.createDecipher('aes-256-cbc', secretKey);
    let decrypted = decipher.update(encryptedSolde, 'binary', 'utf8');
    decrypted += decipher.final('utf8');
    return parseFloat(decrypted);
  } catch (err) {
    console.error("Erreur lors du décryptage du solde :", err);
    return null;
  }
}

/**
 * Chiffre un solde en clair avec la clé du compte.
 * @param {number} solde - Le solde en clair.
 * @param {string} secretKey - La clé secrète associée.
 * @returns {string|null} - Le solde chiffré ou null en cas d'erreur.
 */
function encryptSolde(solde, secretKey) {
  try {
    const cipher = crypto.createCipher('aes-256-cbc', secretKey);
    let encrypted = cipher.update(solde.toString(), 'utf8', 'binary');
    encrypted += cipher.final('binary');
    return encrypted;
  } catch (err) {
    console.error("Erreur lors de l'encryptage du solde :", err);
    return null;
  }
}

/* ============================================================
   Journalisation des tentatives de connexion
   ============================================================ */

/**
 * Enregistre une tentative de connexion dans la table login_attempts.
 * @param {string} username - Le nom d'utilisateur utilisé.
 * @param {string} ip - L'adresse IP de la requête.
 * @param {boolean} success - Vrai si la connexion a réussi, faux sinon.
 * @param {string} message - Message complémentaire.
 */
function logLoginAttempt(username, ip, success, message) {
  const sql = `
    INSERT INTO login_attempts (username, ip, attempt_time, success, message)
    VALUES (?, ?, NOW(), ?, ?);
  `;
  db.query(sql, [username, ip, success ? 1 : 0, message], (err) => {
    if (err) {
      console.error("Erreur lors de l'enregistrement de la tentative de connexion :", err);
    }
  });
}

/* ============================================================
   Routes de l'API de base
   ============================================================ */

app.get('/api', (req, res) => {
  res.send('API is working');
});

// Exemple de route pour récupérer des utilisateurs (à adapter selon vos besoins)
app.get('/api/auth', (req, res) => {
  db.query("SELECT * FROM utilisateurs", (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.status(200).send(results);
    }
  });
});

/* ============================================================
   Authentification via JWT et gestion des login_attempts
   ============================================================ */

/**
 * Route de login.
 * Attendu dans le body : { username, password }
 */
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  if (!username || !password) {
    logLoginAttempt(username, ip, false, "Paramètres manquants");
    return res.status(400).send({ error: "Paramètres manquants" });
  }

  const sql = "SELECT * FROM utilisateurs WHERE nom_utilisateur = ?;";
  db.query(sql, [username], (err, results) => {
    if (err) {
      logLoginAttempt(username, ip, false, "Erreur base de données");
      console.error(err);
      return res.status(500).send({ error: "Erreur base de données" });
    }
    if (results.length === 0) {
      logLoginAttempt(username, ip, false, "Utilisateur non trouvé");
      return res.status(401).send({ error: "Utilisateur non trouvé" });
    }
    const user = results[0];

    // Comparaison du mot de passe avec bcrypt pour être cohérent avec PHP (password_hash)
    bcrypt.compare(password, user.mot_de_passe_hache, (err, isMatch) => {
      if (err || !isMatch) {
        logLoginAttempt(username, ip, false, "Mot de passe invalide");
        return res.status(401).send({ error: "Mot de passe invalide" });
      }

      logLoginAttempt(username, ip, true, "Connexion réussie");

      // Génération d'un token JWT valable 1 heure
      const token = jwt.sign(
        { id: user.identifiant, role: user.role },
        JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.status(200).send({ token });
    });
  });
});

/**
 * Middleware pour vérifier le token JWT dans l'en-tête Authorization.
 */
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).send({ error: "Token manquant" });
  }
  // Format attendu : "Bearer <token>"
  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).send({ error: "Token mal formaté" });
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error("Erreur de vérification du token :", err);
      return res.status(401).send({ error: "Token invalide ou expiré" });
    }
    req.user = decoded; // Ajoute les informations du token à la requête (ex: id, role)
    next();
  });
}

/* ============================================================
   Endpoint de transaction NFC
   ============================================================ */

/**
 * Route pour traiter une transaction NFC.
 * Attendu dans le body (format JSON) :
 * - amount  : montant de la transaction
 * - pin     : code PIN saisi (doit correspondre à celui du compte payeur)
 * - nfcData : token NFC lu sur la carte (doit correspondre à comptes.token_nfc)
 * - user_id : identifiant du commerçant (utilisateur authentifié)
 */
app.post('/api/transaction', verifyToken, (req, res) => {
  const { amount, pin, nfcData, user_id } = req.body;

  if (!amount || !pin || !nfcData || !user_id) {
    return res.status(400).send({ error: "Paramètres manquants" });
  }

  // nfcData correspond ici au token NFC lu sur la carte du payeur.
  const nfcToken = nfcData;

  // Récupérer le compte du payeur en fonction du token NFC
  const payerQuery = `
    SELECT c.compte_id, c.solde_chiffre, c.cle_secrete, u.code_pin, u.identifiant 
    FROM comptes c 
    INNER JOIN utilisateurs u ON u.identifiant = c.utilisateur_id
    WHERE c.token_nfc = ?;
  `;
  db.query(payerQuery, [nfcToken], (err, payerResults) => {
    if (err) {
      console.error(err);
      return res.status(500).send({ error: "Erreur base de données (payeur)" });
    }
    if (payerResults.length === 0) {
      return res.status(404).send({ error: "Compte payeur non trouvé" });
    }
    const payer = payerResults[0];

    // Vérifier que le code PIN fourni correspond à celui stocké dans le compte payeur
    if (pin !== payer.code_pin) {
      return res.status(401).send({ error: "Code PIN invalide" });
    }

    // Déchiffrer le solde du payeur
    const payerBalance = decryptSolde(payer.solde_chiffre, payer.cle_secrete);
    if (payerBalance === null) {
      return res.status(500).send({ error: "Échec du décryptage du solde du payeur" });
    }
    if (payerBalance < parseFloat(amount)) {
      return res.status(400).send({ error: "Fonds insuffisants sur le compte du payeur" });
    }

    // Récupérer le compte du commerçant à partir de l'identifiant utilisateur (user_id)
    const merchantQuery = `
      SELECT c.compte_id, c.solde_chiffre, c.cle_secrete, c.historique 
      FROM comptes c 
      WHERE c.utilisateur_id = ?;
    `;
    db.query(merchantQuery, [user_id], (err, merchantResults) => {
      if (err) {
        console.error(err);
        return res.status(500).send({ error: "Erreur base de données (commerçant)" });
      }
      if (merchantResults.length === 0) {
        return res.status(404).send({ error: "Compte commerçant non trouvé" });
      }
      const merchant = merchantResults[0];

      // Déchiffrer le solde du commerçant
      const merchantBalance = decryptSolde(merchant.solde_chiffre, merchant.cle_secrete);
      if (merchantBalance === null) {
        return res.status(500).send({ error: "Échec du décryptage du solde du commerçant" });
      }

      // Calculer les nouveaux soldes
      const newPayerBalance = payerBalance - parseFloat(amount);
      const newMerchantBalance = merchantBalance + parseFloat(amount);

      // Rechiffrer les nouveaux soldes
      const newEncryptedPayerBalance = encryptSolde(newPayerBalance, payer.cle_secrete);
      const newEncryptedMerchantBalance = encryptSolde(newMerchantBalance, merchant.cle_secrete);

      if (!newEncryptedPayerBalance || !newEncryptedMerchantBalance) {
        return res.status(500).send({ error: "Échec du chiffrement des soldes mis à jour" });
      }

      // Mise à jour du solde du compte payeur
      const updatePayerQuery = `UPDATE comptes SET solde_chiffre = ? WHERE compte_id = ?;`;
      db.query(updatePayerQuery, [newEncryptedPayerBalance, payer.compte_id], (err, updatePayerResult) => {
        if (err) {
          console.error(err);
          return res.status(500).send({ error: "Échec de la mise à jour du compte payeur" });
        }

        // Mise à jour du solde du compte commerçant
        const updateMerchantQuery = `UPDATE comptes SET solde_chiffre = ? WHERE compte_id = ?;`;
        db.query(updateMerchantQuery, [newEncryptedMerchantBalance, merchant.compte_id], (err, updateMerchantResult) => {
          if (err) {
            console.error(err);
            return res.status(500).send({ error: "Échec de la mise à jour du compte commerçant" });
          }

          // (Optionnel) Vous pouvez enregistrer l'opération dans l'historique des transactions du compte ici
          return res.status(200).send({ message: "Transaction réalisée avec succès" });
        });
      });
    });
  });
});

/* ============================================================
   Démarrage du serveur
   ============================================================ */
const PORT = process.env.STATUS === 'development' ? process.env.DEV_PORT : process.env.PROD_PORT;
if (!PORT) {
  console.error('Error: The PORT environment variable is not set.');
  process.exit(1);
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}.`);
});
