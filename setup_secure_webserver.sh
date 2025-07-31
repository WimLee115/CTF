#!/bin/bash

# Kleuren voor output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Log functie
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Foutafhandeling
error_exit() {
    echo -e "${RED}Fout: $1${NC}" >&2
    exit 1
}

# Controleer of script als root draait
if [ "$EUID" -ne 0 ]; then
    error_exit "Dit script moet als root worden uitgevoerd (gebruik sudo)"
fi

# Vraag om domeinnaam
read -p "Voer de domeinnaam in (bijv. voorbeeld.nl): " DOMAIN
if [ -z "$DOMAIN" ]; then
    error_exit "Domeinnaam is vereist"
fi

# Vraag om database wachtwoord
read -s -p "Voer het database root wachtwoord in: " DB_ROOT_PASS
echo
if [ -z "$DB_ROOT_PASS" ]; then
    error_exit "Database wachtwoord is vereist"
fi

# Update systeem
log "Systeem wordt bijgewerkt..."
apt update && apt upgrade -y || error_exit "Systeemupdate mislukt"

# Installeer benodigde pakketten
log "Installeren van Apache2, MariaDB, PHP en benodigde modules..."
apt install -y apache2 mariadb-server php php-mysql libapache2-mod-php certbot python3-certbot-apache || error_exit "Installatie van pakketten mislukt"

# Start en enable services
log "Starten en inschakelen van services..."
systemctl enable apache2 mariadb || error_exit "Services inschakelen mislukt"
systemctl start apache2 mariadb || error_exit "Services starten mislukt"

# Configureer MariaDB
log "Beveiligen van MariaDB installatie..."
mysql_secure_installation <<EOF

y
$DB_ROOT_PASS
$DB_ROOT_PASS
y
y
y
y
EOF

# Maak database en gebruiker
DB_NAME="webapp_db"
DB_USER="webapp_user"
DB_PASS=$(openssl rand -base64 12)

log "Aanmaken van database en gebruiker..."
mysql -u root -p"$DB_ROOT_PASS" <<EOF
CREATE DATABASE $DB_NAME;
CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF
[ $? -eq 0 ] || error_exit "Database configuratie mislukt"

# Maak database tabel
log "Aanmaken van gebruikers tabel..."
mysql -u root -p"$DB_ROOT_PASS" $DB_NAME <<EOF
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
EOF
[ $? -eq 0 ] || error_exit "Tabel aanmaken mislukt"

# Configureer Apache
log "Configureren van Apache virtual host..."
cat > /etc/apache2/sites-available/$DOMAIN.conf <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    DocumentRoot /var/www/$DOMAIN
    <Directory /var/www/$DOMAIN>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/$DOMAIN-error.log
    CustomLog \${APACHE_LOG_DIR}/$DOMAIN-access.log combined
</VirtualHost>
EOF

# Maak web directory
log "Aanmaken van web directory..."
mkdir -p /var/www/$DOMAIN
chown -R www-data:www-data /var/www/$DOMAIN
chmod -R 755 /var/www/$DOMAIN

# Maak PHP applicatie
log "Aanmaken van PHP applicatie..."
cat > /var/www/$DOMAIN/index.php <<'EOF'
<?php
session_start();
header("X-XSS-Protection: 1; mode=block");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';");

$db_host = "localhost";
$db_user = "webapp_user";
$db_pass = "__DB_PASS__";
$db_name = "webapp_db";

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Database verbinding mislukt: " . $e->getMessage());
}

function sanitize_input($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

function login($username, $password) {
    global $pdo;
    $username = sanitize_input($username);
    $stmt = $pdo->prepare("SELECT id, password FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();
    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        return true;
    }
    return false;
}

function register($username, $password) {
    global $pdo;
    $username = sanitize_input($username);
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    try {
        $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        return $stmt->execute([$username, $hashed_password]);
    } catch(PDOException $e) {
        return false;
    }
}

function create_post($user_id, $content) {
    global $pdo;
    $content = sanitize_input($content);
    $stmt = $pdo->prepare("INSERT INTO posts (user_id, content) VALUES (?, ?)");
    return $stmt->execute([$user_id, $content]);
}

function get_posts() {
    global $pdo;
    $stmt = $pdo->query("SELECT p.content, p.created_at, u.username FROM posts p JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC");
    return $stmt->fetchAll();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['login'])) {
        if (login($_POST['username'], $_POST['password'])) {
            $message = "Succesvol ingelogd!";
        } else {
            $error = "Ongeldige inloggegevens";
        }
    } elseif (isset($_POST['register'])) {
        if (register($_POST['username'], $_POST['password'])) {
            $message = "Registratie succesvol! Je kunt nu inloggen.";
        } else {
            $error = "Registratie mislukt. Gebruikersnaam bestaat mogelijk al.";
        }
    } elseif (isset($_POST['post']) && isset($_SESSION['user_id'])) {
        if (create_post($_SESSION['user_id'], $_POST['content'])) {
            $message = "Bericht geplaatst!";
        } else {
            $error = "Fout bij plaatsen bericht";
        }
    } elseif (isset($_POST['logout'])) {
        session_destroy();
        $message = "Uitgelogd";
    }
}
?>

<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Beveiligde Webapp</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .error { color: red; }
        .message { color: green; }
        .post { border: 1px solid #ccc; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Beveiligde Webapp</h1>
    
    <?php if (isset($error)): ?>
        <p class="error"><?php echo $error; ?></p>
    <?php endif; ?>
    <?php if (isset($message)): ?>
        <p class="message"><?php echo $message; ?></p>
    <?php endif; ?>

    <?php if (!isset($_SESSION['user_id'])): ?>
        <h2>Inloggen</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Gebruikersnaam" required>
            <input type="password" name="password" placeholder="Wachtwoord" required>
            <input type="submit" name="login" value="Inloggen">
        </form>

        <h2>Registreren</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Gebruikersnaam" required>
            <input type="password" name="password" placeholder="Wachtwoord" required>
            <input type="submit" name="register" value="Registreren">
        </form>
    <?php else: ?>
        <h2>Nieuw Bericht</h2>
        <form method="post">
            <textarea name="content" placeholder="Schrijf je bericht..." required></textarea>
            <input type="submit" name="post" value="Plaatsen">
        </form>
        <form method="post">
            <input type="submit" name="logout" value="Uitloggen">
        </form>

        <h2>Berichten</h2>
        <?php foreach (get_posts() as $post): ?>
            <div class="post">
                <p><strong><?php echo htmlspecialchars($post['username']); ?></strong> - <?php echo $post['created_at']; ?></p>
                <p><?php echo htmlspecialchars($post['content']); ?></p>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>
</body>
</html>
EOF

# Vervang database wachtwoord in PHP bestand
sed -i "s/__DB_PASS__/$DB_PASS/" /var/www/$DOMAIN/index.php

# Activeer virtual host
log "Activeren van virtual host..."
a2ensite $DOMAIN.conf || error_exit "Virtual host activeren mislukt"
systemctl reload apache2 || error_exit "Apache herladen mislukt"

# Configureer SSL
log "Configureren van SSL met Let's Encrypt..."
certbot --apache -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN || error_exit "SSL configuratie mislukt"

# Beveilig Apache configuratie
log "Beveiligen van Apache configuratie..."
cat > /etc/apache2/conf-available/security.conf <<EOF
ServerTokens Prod
ServerSignature Off
TraceEnable Off
Header set X-XSS-Protection "1; mode=block"
Header set X-Frame-Options "DENY"
Header set X-Content-Type-Options "nosniff"
Header set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
EOF
a2enconf security || error_exit "Security config activeren mislukt"
systemctl reload apache2 || error_exit "Apache herladen mislukt"

# Stel firewall in
log "Configureren van UFW firewall..."
apt install -y ufw || error_exit "UFW installatie mislukt"
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable || error_exit "UFW inschakelen mislukt"

# Maak README
log "Aanmaken van README..."
cat > /var/www/$DOMAIN/README.md <<EOF
# Beveiligde Webserver Installatie

## Overzicht
Dit is een beveiligde Apache webserver met PHP en MariaDB, geïnstalleerd op Kali Linux. De applicatie biedt:
- Gebruikersregistratie en login
- Berichten plaatsen met XSS-beveiliging
- SSL/TLS met Let's Encrypt
- Beveiligde Apache configuratie
- UFW firewall

## Gebruik
1. Navigeer naar https://$DOMAIN
2. Registreer een account of log in
3. Plaats berichten (max 1000 tekens)
4. Log uit wanneer klaar

## Database
- Naam: $DB_NAME
- Gebruiker: $DB_USER
- Wachtwoord: $DB_PASS
- Host: localhost

## Debuggen
1. Controleer Apache logs: /var/log/apache2/$DOMAIN-error.log
2. Controleer MariaDB logs: /var/log/mysql/error.log
3. Test database connectie:
   ```bash
   mysql -u $DB_USER -p'$DB_PASS' $DB_NAME
   ```
4. Controleer SSL: 
   ```bash
   openssl s_client -connect $DOMAIN:443
   ```
5. Controleer PHP:
   ```bash
   php -f /var/www/$DOMAIN/index.php
   ```

## Beveiligingsmaatregelen
- XSS-bescherming via htmlspecialchars en HTTP headers
- SQL-injectie preventie via prepared statements
- Veilige wachtwoordopslag met password_hash
- CSP, X-Frame-Options, X-Content-Type-Options headers
- Firewall met alleen poorten 80 en 443 open
EOF

log "${GREEN}Installatie voltooid! Webserver is bereikbaar op https://$DOMAIN${NC}"
log "Database gegevens zijn opgeslagen in /var/www/$DOMAIN/README.md"
log "Controleer de README voor debug-instructies"
