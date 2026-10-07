# flexisip-http-file-transfer-server — included by the vhost only.
Alias /files/tmp /var/opt/belledonne-communications/flexisip-http-file-transfer-tmp
Alias /files     /opt/belledonne-communications/share/flexisip-http-file-transfer-server

<Directory /opt/belledonne-communications/share/flexisip-http-file-transfer-server/>
    Options -Indexes
    AllowOverride None
    Require all granted
    # php-fpm: pass Authorization to PHP
    CGIPassAuth On
    <Files "download.php">
        Require all denied
    </Files>

    Header always unset X-Powered-By
    Header unset X-Powered-By

    # CORS for Trix
    Header always set Access-Control-Allow-Origin "https://trix.weshwesh.eu"
    Header always set Access-Control-Allow-Methods "POST, OPTIONS"
    Header always set Access-Control-Allow-Headers "Authorization, From, Content-Type"
    Header always set Access-Control-Expose-Headers "WWW-Authenticate"
    Header always set Access-Control-Max-Age "86400"
    Header always append Vary "Origin"

    # Preflight answered by Apache, not challenged
    RewriteEngine On
    RewriteCond %{REQUEST_METHOD} OPTIONS
    RewriteRule ^ - [R=204,L]
</Directory>

<Directory /var/opt/belledonne-communications/flexisip-http-file-transfer-tmp/>
    Options -Indexes -ExecCGI
    AllowOverride None
    Require all granted
    # Never execute an upload
    <FilesMatch ".*">
        SetHandler none
    </FilesMatch>
    Header always set X-Content-Type-Options "nosniff"
    Header always set Content-Disposition "attachment"
    Header always set Access-Control-Allow-Origin "https://trix.weshwesh.eu"
    Header always append Vary "Origin"
</Directory>
