# flexisip-http-file-transfer-server 524ab71 + common-pdo.patch
# (docs/design/chat-media-plan.md, S0). Included by the vhost only, never
# loaded on its own: its name does not end in .conf.
# Downloads are static: the random name is the capability (DESIGN-CHAT-MEDIA §2.7).
Alias /files/tmp /var/opt/belledonne-communications/flexisip-http-file-transfer-tmp
Alias /files     /opt/belledonne-communications/share/flexisip-http-file-transfer-server

<Directory /opt/belledonne-communications/share/flexisip-http-file-transfer-server/>
    Options -Indexes
    AllowOverride None
    Require all granted
    # php-fpm: without it the Authorization header never reaches the PHP
    CGIPassAuth On
    <Files "download.php">
        Require all denied
    </Files>

    # CORS for Trix. "always" so the 401 carries them too, or the browser
    # hides the challenge from the client.
    Header always set Access-Control-Allow-Origin "https://trix.weshwesh.eu"
    Header always set Access-Control-Allow-Methods "POST, OPTIONS"
    Header always set Access-Control-Allow-Headers "Authorization, From, Content-Type"
    Header always set Access-Control-Expose-Headers "WWW-Authenticate"
    Header always set Access-Control-Max-Age "86400"
    Header always append Vary "Origin"

    # The preflight is answered here, never challenged by the PHP
    RewriteEngine On
    RewriteCond %{REQUEST_METHOD} OPTIONS
    RewriteRule ^ - [R=204,L]
</Directory>

<Directory /var/opt/belledonne-communications/flexisip-http-file-transfer-tmp/>
    Options -Indexes -ExecCGI
    AllowOverride None
    Require all granted
    # No script ever runs from the upload directory, whatever its extension
    <FilesMatch ".*">
        SetHandler none
    </FilesMatch>
    Header always set X-Content-Type-Options "nosniff"
    Header always set Content-Disposition "attachment"
    # Trix reads the file with fetch() to build a blob URL
    Header always set Access-Control-Allow-Origin "https://trix.weshwesh.eu"
    Header always append Vary "Origin"
</Directory>
