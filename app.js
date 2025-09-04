// Wir importieren die benötigten Module
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcrypt';
import session from 'express-session';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Die gesamte App-Logik in eine asynchrone Funktion packen
async function startApp() {
  // Datenbankverbindung asynchron öffnen
  const dbPath = path.join(__dirname, 'shopping_list.db');
  const db = await open({
    filename: dbPath,
    driver: sqlite3.Database
  });

  // Tabelle für die Benutzer erstellen
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    );
  `);

  // Tabelle für die Einkaufsliste erstellen
  await db.exec(`
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      product TEXT NOT NULL,
      quantity TEXT,
      notes TEXT,
      purchased INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  // Lösche alle Artikel, die älter als 14 Tage sind
  const retentionPeriod = 14;
  const cutOffDate = new Date(new Date().setDate(new Date().getDate() - retentionPeriod));
  
  await db.run('DELETE FROM items WHERE purchased = 1 AND created_at <= ?', cutOffDate.toISOString());
  console.log(`Ältere gekaufte Artikel (älter als ${retentionPeriod} Tage) wurden gelöscht.`);

  // ---
  const saltRounds = 10;
  const hashedPassword1 = await bcrypt.hash('deinPasswort', saltRounds);
  const hashedPassword2 = await bcrypt.hash('passwortDeinerFreundin', saltRounds);

  try {
    await db.run('INSERT INTO users (username, password) VALUES (?, ?)', 'deinUsername', hashedPassword1);
    await db.run('INSERT INTO users (username, password) VALUES (?, ?)', 'ihrUsername', hashedPassword2);
    console.log('Beide Benutzer wurden erfolgreich erstellt!');
  } catch (e) {
    if (e.code !== 'SQLITE_CONSTRAINT') {
      console.error('Fehler beim Einfügen der Benutzer:', e);
    } else {
      console.log('Benutzer existieren bereits.');
    }
  }

  // ---

  // Wir erstellen eine Instanz unserer Anwendung
  const app = express();
  const port = 3000;

  // Middleware, die Formular-Daten verarbeitet.
  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());

  // Express-Session Middleware konfigurieren
  app.use(session({
    secret: 'dein-super-geheimes-geheimnis',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 1000 * 60 * 60 * 24 }
  }));

  // Middleware, die prüft, ob der Benutzer angemeldet ist
  function isAuthenticated(req, res, next) {
    if (req.session.userId) {
      next();
    } else {
      res.redirect('/');
    }
  };

  // Wir konfigurieren Express für unsere EJS-Templates und den Public-Ordner
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.use(express.static(path.join(__dirname, 'public')));

  // --- Routen-Definitionen ---

  // GET-Route für die Startseite (die Login-Seite)
  app.get('/', (req, res) => {
    res.render('index');
  });

  // POST-Route für das Login-Formular
  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.get('SELECT * FROM users WHERE username = ?', username);

    if (!user) {
      console.log(`Anmeldeversuch fehlgeschlagen: Benutzer '${username}' existiert nicht.`);
      return res.send('Anmeldeversuch fehlgeschlagen: Falscher Benutzername oder falsches Passwort.');
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (isPasswordCorrect) {
      req.session.userId = user.id;
      console.log(`Anmeldeversuch erfolgreich für: ${username}.`);
      res.redirect('/shopping');
    } else {
      console.log(`Anmeldeversuch fehlgeschlagen: Falsches Passwort für ${username}.`);
      res.send('Anmeldeversuch fehlgeschlagen: Falscher Benutzername oder falsches Passwort.');
    }
  });
  
  // POST-Route zum Hinzufügen eines Artikels (CREATE)
  app.post('/add', isAuthenticated, async (req, res) => {
    const { product, quantity, notes } = req.body;
    const userId = req.session.userId;
    if (!product) {
      return res.status(400).send('Produktname ist erforderlich.');
    }

    await db.run('INSERT INTO items (user_id, product, quantity, notes) VALUES (?, ?, ?, ?)', 
      userId, 
      product, 
      quantity || null, 
      notes || null
    );

    res.redirect('/shopping');
  });

  // --- GEÄNDERTE ROUTEN FÜR GEMEINSAME VERWALTUNG ---

  // POST-Route zum Markieren eines Artikels als "gekauft" (UPDATE)
  app.post('/purchase', isAuthenticated, async (req, res) => {
    const { id } = req.body;
    await db.run('UPDATE items SET purchased = 1 WHERE id = ?', id);
    res.redirect('/shopping');
  });

  // POST-Route zum Löschen eines Artikels (DELETE)
  app.post('/delete', isAuthenticated, async (req, res) => {
    const { id } = req.body;
    await db.run('DELETE FROM items WHERE id = ?', id);
    res.redirect('/shopping');
  });

  // ---

  // Geschützte Route für die Einkaufsliste (READ)
  app.get('/shopping', isAuthenticated, async (req, res) => {
    const shoppingList = await db.all('SELECT * FROM items WHERE purchased = 0 ORDER BY id DESC');
    res.render('shopping', { shoppingList: shoppingList });
  });

  // Geschützte Route für die Historie (READ)
app.get('/history', isAuthenticated, async (req, res) => {
  // Hole ALLE GEKAUFTEN Artikel, ohne nach user_id zu filtern!
  const historyList = await db.all('SELECT * FROM items WHERE purchased = 1 ORDER BY id DESC');
  res.render('history', { historyList: historyList });
});

  // Logout-Route
  app.get('/logout', (req, res) => {
    req.session.destroy(err => {
      if (err) {
        return res.redirect('/shopping');
      }
      res.clearCookie('connect.sid');
      res.redirect('/');
    });
  });

  // Server starten
  app.listen(port, () => {
    console.log(`Server läuft auf http://localhost:${port}`);
  });
}

// Die Funktion aufrufen, um die App zu starten
startApp();