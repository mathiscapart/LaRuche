# syntax=docker/dockerfile:1
# Reverse-proxy Apache devant le honeypot HTTP (FastAPI). Objectif anti-détection :
#  - en-têtes / pages d'erreur / version Apache authentiques : Apache/2.4.57 (Debian) ;
#  - assets statiques WordPress RÉELS servis depuis le disque (vrais ETag / Last-Modified
#    / Accept-Ranges, contenu byte-exact => résiste au fingerprint WPScan) ;
#  - tout le dynamique proxifié vers le backend FastAPI (honeypot-http:8080).
FROM debian:bookworm-slim

# Apache + extraction des SEULS fichiers statiques de WordPress 6.5.2 (pas de .php :
# sans mod_php, Apache divulguerait sinon le code source des .php).
# hadolint ignore=DL3008,DL3015
RUN apt-get update \
 && apt-get install -y --no-install-recommends apache2 ca-certificates curl unzip \
 && a2enmod proxy proxy_http headers rewrite \
 && curl -fsSL https://wordpress.org/wordpress-6.5.2.zip -o /tmp/wp.zip \
 && unzip -q /tmp/wp.zip -d /tmp \
 && cd /tmp/wordpress \
 && find wp-includes wp-content wp-admin -type f \
      \( -name '*.css' -o -name '*.js' -o -name '*.map' -o -name '*.png' -o -name '*.jpg' \
         -o -name '*.jpeg' -o -name '*.gif' -o -name '*.svg' -o -name '*.ico' \
         -o -name '*.woff' -o -name '*.woff2' -o -name '*.ttf' -o -name '*.eot' \) \
      -exec cp --parents -t /var/www/html {} + \
 && cp readme.html license.txt /var/www/html/ \
 && chown -R www-data:www-data /var/www/html \
 && sed -i 's/^ServerTokens .*/ServerTokens OS/' /etc/apache2/conf-available/security.conf \
 && sed -i 's/^ServerSignature .*/ServerSignature On/' /etc/apache2/conf-available/security.conf \
 && rm -rf /tmp/wp.zip /tmp/wordpress /var/lib/apt/lists/*

COPY honeypot.conf /etc/apache2/sites-available/000-default.conf

# Valide la syntaxe de la conf au build (échoue le build si la conf est invalide).
RUN apache2ctl configtest

EXPOSE 80
# Apache en avant-plan comme PID 1.
CMD ["apache2ctl", "-D", "FOREGROUND"]
