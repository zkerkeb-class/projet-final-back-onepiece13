const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const jwt     = require('jsonwebtoken');
const bcrypt  = require('bcryptjs');

const app  = express();
const PORT = process.env.PORT || 3001;

// ─────────────────────────────────────────────────────────────────────────────
// CONFIG JWT
// ─────────────────────────────────────────────────────────────────────────────
const JWT_SECRET  = process.env.JWT_SECRET  || 'onepiece_super_secret_dev_key_2026';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '2h';

// Middleware
app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────────────────────────────────────
// DATA PERSISTENCE HELPERS
// ─────────────────────────────────────────────────────────────────────────────
const DB_PATH    = path.join(__dirname, 'onepieceguess_database.json');
const USERS_PATH = path.join(__dirname, 'users.json');

function loadJSON(p)      { return JSON.parse(fs.readFileSync(p, 'utf-8')); }
function saveJSON(p, data) { fs.writeFileSync(p, JSON.stringify(data, null, 2), 'utf-8'); }

// Load database
let characters = [];
try {
  characters = loadJSON(DB_PATH);
  console.log(`✅ Base de données chargée : ${characters.length} personnages`);
} catch (err) {
  console.error('❌ Erreur lors du chargement de la base de données :', err.message);
  process.exit(1);
}

// ── Load / init users ─────────────────────────────────────────────────────────
let users = [];
if (!fs.existsSync(USERS_PATH)) {
  users = [{
    id: 1, username: 'admin',
    password: bcrypt.hashSync('onepiece', 10),
    role: 'admin', createdAt: new Date().toISOString()
  }];
  saveJSON(USERS_PATH, users);
  console.log('✅ Utilisateur admin créé (admin / onepiece)');
} else {
  users = loadJSON(USERS_PATH);
  console.log(`✅ ${users.length} utilisateur(s) chargé(s)`);
}

// ─────────────────────────────────────────────────────────────────────────────
// TOKEN BLACKLIST — logout + invalidation forcée
// In-memory (en prod : Redis). La liste se réinitialise au redémarrage,
// ce qui est acceptable car les tokens expirés (2h) deviennent inactifs seuls.
// ─────────────────────────────────────────────────────────────────────────────
const tokenBlacklist = new Set();

// ─────────────────────────────────────────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token manquant — veuillez vous connecter' });
  }
  const token = authHeader.slice(7);
  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ error: 'Token invalide (déconnecté)' });
  }
  try {
    req.user  = jwt.verify(token, JWT_SECRET);
    req.token = token;
    next();
  } catch {
    return res.status(401).json({ error: 'Token expiré ou invalide' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Accès réservé aux administrateurs' });
  }
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// ROUTES — AUTH
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Champs "username" et "password" requis' });

  const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Identifiants incorrects' });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

// POST /api/auth/logout  (protégé)
app.post('/api/auth/logout', requireAuth, (req, res) => {
  tokenBlacklist.add(req.token);
  res.json({ message: 'Déconnexion réussie' });
});

// GET /api/auth/me  (protégé)
app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  res.json({ id: user.id, username: user.username, role: user.role, createdAt: user.createdAt });
});

// POST /api/auth/signup  (public — crée un compte "user" sans token)
app.post('/api/auth/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Champs "username" et "password" requis' });
  if (password.length < 4)
    return res.status(400).json({ error: 'Mot de passe trop court (4 caractères min.)' });
  if (users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(409).json({ error: 'Ce nom d\'utilisateur est déjà pris' });

  const newUser = {
    id: users.length ? Math.max(...users.map(u => u.id)) + 1 : 1,
    username,
    password: bcrypt.hashSync(password, 10),
    role: 'user',
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  saveJSON(USERS_PATH, users);

  const token = jwt.sign(
    { id: newUser.id, username: newUser.username, role: newUser.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
  res.status(201).json({ token, user: { id: newUser.id, username: newUser.username, role: newUser.role } });
});

// POST /api/auth/register  (admin uniquement)
app.post('/api/auth/register', requireAuth, requireAdmin, (req, res) => {
  const { username, password, role = 'user' } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Champs "username" et "password" requis' });
  if (users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(409).json({ error: 'Ce nom d\'utilisateur existe déjà' });

  const newUser = {
    id: users.length ? Math.max(...users.map(u => u.id)) + 1 : 1,
    username,
    password: bcrypt.hashSync(password, 10),
    role: ['admin', 'user'].includes(role) ? role : 'user',
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  saveJSON(USERS_PATH, users);
  res.status(201).json({ id: newUser.id, username: newUser.username, role: newUser.role });
});

// GET /api/auth/users  (admin uniquement)
app.get('/api/auth/users', requireAuth, requireAdmin, (req, res) => {
  res.json(users.map(u => ({ id: u.id, username: u.username, role: u.role, createdAt: u.createdAt })));
});

// DELETE /api/auth/users/:id  (admin uniquement)
app.delete('/api/auth/users/:id', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id)
    return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte' });
  const idx = users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: `Utilisateur introuvable` });
  const [deleted] = users.splice(idx, 1);
  saveJSON(USERS_PATH, users);
  res.json({ message: `Compte "${deleted.username}" supprimé` });
});

// ─────────────────────────────────────────────────────────────────────────────
// ROUTES — CHARACTERS CRUD (protégées)
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/characters  — Créer
app.post('/api/characters', requireAuth, (req, res) => {
  const data = req.body;
  if (!data.personnage)
    return res.status(400).json({ error: 'Le champ "personnage" est obligatoire' });
  if (characters.find(c => c.personnage.toLowerCase() === data.personnage.toLowerCase()))
    return res.status(409).json({ error: `Le personnage "${data.personnage}" existe déjà` });
  characters.push(data);
  saveJSON(DB_PATH, characters);
  res.status(201).json(data);
});

// PUT /api/characters/:name  — Modifier
app.put('/api/characters/:name', requireAuth, (req, res) => {
  const idx = characters.findIndex(c => c.personnage.toLowerCase() === req.params.name.toLowerCase());
  if (idx === -1) return res.status(404).json({ error: `Personnage "${req.params.name}" introuvable` });
  characters[idx] = { ...characters[idx], ...req.body, personnage: characters[idx].personnage };
  saveJSON(DB_PATH, characters);
  res.json(characters[idx]);
});

// DELETE /api/characters/:name  — Supprimer
app.delete('/api/characters/:name', requireAuth, (req, res) => {
  const idx = characters.findIndex(c => c.personnage.toLowerCase() === req.params.name.toLowerCase());
  if (idx === -1) return res.status(404).json({ error: `Personnage "${req.params.name}" introuvable` });
  const [deleted] = characters.splice(idx, 1);
  saveJSON(DB_PATH, characters);
  res.json({ message: `"${deleted.personnage}" supprimé`, deleted });
});

// ─────────────────────────────────────────────────────────────────────────────
// ROUTES — PUBLIQUES
// ─────────────────────────────────────────────────────────────────────────────

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'OnePieceGuess API fonctionne correctement',
    totalCharacters: characters.length,
    timestamp: new Date().toISOString()
  });
});

// Get all characters
app.get('/api/characters', (req, res) => {
  const { search, affiliation, genre } = req.query;
  let result = [...characters];

  if (search) {
    const q = search.toLowerCase();
    result = result.filter(c => c.personnage.toLowerCase().includes(q));
  }
  if (affiliation) {
    result = result.filter(c => c.affiliation.toLowerCase() === affiliation.toLowerCase());
  }
  if (genre) {
    result = result.filter(c => c.genre.toLowerCase() === genre.toLowerCase());
  }

  res.json(result);
});

// Get character names only (for autocomplete)
app.get('/api/characters/names', (req, res) => {
  const names = characters.map(c => c.personnage);
  res.json(names);
});

// Get a random character (for daily challenge)
app.get('/api/characters/random', (req, res) => {
  const random = characters[Math.floor(Math.random() * characters.length)];
  res.json(random);
});

// Get daily character (same character all day based on date seed)
app.get('/api/characters/daily', (req, res) => {
  const today = new Date();
  const seed = today.getFullYear() * 10000 + (today.getMonth() + 1) * 100 + today.getDate();
  const index = seed % characters.length;
  const daily = { ...characters[index] };
  // Don't reveal the name
  res.json({ index, total: characters.length });
});

// Check a guess
app.post('/api/guess', (req, res) => {
  const { guess, targetName } = req.body;

  if (!guess || !targetName) {
    return res.status(400).json({ error: 'Les champs "guess" et "targetName" sont requis' });
  }

  const guessChar = characters.find(
    c => c.personnage.toLowerCase() === guess.toLowerCase()
  );
  const targetChar = characters.find(
    c => c.personnage.toLowerCase() === targetName.toLowerCase()
  );

  if (!guessChar) {
    return res.status(404).json({ error: `Personnage "${guess}" introuvable` });
  }
  if (!targetChar) {
    return res.status(404).json({ error: `Cible "${targetName}" introuvable` });
  }

  const result = compareCharacters(guessChar, targetChar);
  res.json({
    guess: guessChar,
    correct: guess.toLowerCase() === targetName.toLowerCase(),
    comparison: result
  });
});

// Get character by name (en dernier — évite de capturer random/daily/names)
app.get('/api/characters/:name', (req, res) => {
  const char = characters.find(
    c => c.personnage.toLowerCase() === req.params.name.toLowerCase()
  );
  if (!char) return res.status(404).json({ error: `Personnage "${req.params.name}" introuvable` });
  res.json(char);
});

// ─── Arc chronology (ordered by first chapter) ────────────────────────────
const ARC_ORDER = [
  'Romance Dawn',        // ch.3
  'Orange Town',         // ch.8
  'Syrup Village',       // ch.23
  'Baratie',             // ch.44
  'Arlong Park',         // ch.92
  'Loguetown',           // ch.97
  'Reverse Mountain',    // ch.103
  'Whisky Peak',         // ch.114
  'Little Garden',       // ch.126
  'Drum Island',         // ch.134
  'Arabasta',            // ch.159
  'Jaya',                // ch.234
  'Skypiea',             // ch.254
  'Long Ring Long Land', // ch.303
  'Water 7',             // ch.329
  'Enies Lobby',         // ch.397
  'Thriller Bark',       // ch.443
  'Sabaody Archipelago', // ch.498
  'Amazon Lily',         // ch.516
  'Impel Down',          // ch.528
  'Post-War',            // ch.583
  'Return to Sabaody',   // ch.600
  'Fish-Man Island',     // ch.651
  'Punk Hazard',         // ch.657
  'Dressrosa',           // ch.705
  'Zou',                 // ch.804
  'Whole Cake Island',   // ch.860
  'Wano Country',        // ch.920
];

// ─── Helper: compare two characters field by field ───────────────────────────
function compareCharacters(guess, target) {
  return {
    personnage: {
      value: guess.personnage,
      correct: guess.personnage === target.personnage
    },
    genre: {
      value: guess.genre,
      correct: guess.genre === target.genre
    },
    affiliation: {
      value: guess.affiliation,
      correct: guess.affiliation === target.affiliation
    },
    fruitDuDemon: (() => {
      const normFruit = c => {
        if (c.fruitDuDemon === 'Aucun') return 'Non';
        const t = c.typeFruitDuDemon;
        return (t === 'Ancient Zoan' || t === 'Mythical Zoan') ? 'Zoan' : t;
      };
      const gVal = normFruit(guess);
      const tVal = normFruit(target);
      return { value: gVal, correct: gVal === tVal };
    })(),
    haki: (() => {
      const split = h => h === 'Aucun' ? [] : h.split(',').map(s => s.trim());
      const gHaki = split(guess.haki);
      const tHaki = split(target.haki);
      const common = gHaki.filter(h => tHaki.includes(h));
      const correct = gHaki.length === tHaki.length && common.length === tHaki.length;
      const partial = !correct && common.length > 0;
      return { value: guess.haki, correct, partial };
    })(),
    dernierePrime: {
      value: guess.dernierePrime,
      correct: guess.dernierePrimeValeur === target.dernierePrimeValeur,
      direction:
        guess.dernierePrimeValeur < target.dernierePrimeValeur ? 'up' :
        guess.dernierePrimeValeur > target.dernierePrimeValeur ? 'down' : 'equal'
    },
    hauteur: {
      value: guess.hauteur,
      correct: guess.hauteurCm === target.hauteurCm,
      direction:
        guess.hauteurCm < target.hauteurCm ? 'up' :
        guess.hauteurCm > target.hauteurCm ? 'down' : 'equal'
    },
    origine: {
      value: guess.origine,
      correct: guess.origine === target.origine
    },
    premierArc: {
      value: guess.premierArc,
      correct: guess.premierArc === target.premierArc,
      direction: (() => {
        const gi = ARC_ORDER.indexOf(guess.premierArc);
        const ti = ARC_ORDER.indexOf(target.premierArc);
        if (gi === -1 || ti === -1 || gi === ti) return 'equal';
        return gi < ti ? 'up' : 'down';
      })()
    },
    debutChapitre: {
      value: guess.debutChapitre,
      correct: guess.debutChapitre === target.debutChapitre,
      direction:
        guess.debutChapitre < target.debutChapitre ? 'up' :
        guess.debutChapitre > target.debutChapitre ? 'down' : 'equal'
    }
  };
}

// ─── Start server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🏴‍☠️  OnePieceGuess API → http://localhost:${PORT}`);
  console.log(`   POST /api/auth/login          Connexion`);
  console.log(`   POST /api/auth/logout         Déconnexion (protégé)`);
  console.log(`   GET  /api/auth/me             Profil (protégé)`);
  console.log(`   POST /api/auth/register       Créer compte (admin)`);
  console.log(`   GET  /api/characters          Liste personnages`);
  console.log(`   POST /api/characters          Créer personnage (protégé)`);
  console.log(`   PUT  /api/characters/:name    Modifier (protégé)`);
  console.log(`   DELETE /api/characters/:name  Supprimer (protégé)\n`);
});
