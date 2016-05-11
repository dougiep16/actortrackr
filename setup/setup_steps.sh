#Actor DB Web Server setup

###################################################################
# Apache
###################################################################

apt-get -y install apache2
apt-get -y install libapache2-mod-wsgi-py3

###################################################################
# MariaDB
###################################################################

#Important note root password when going thru this, its needed for phpmyadmin and the application

sudo apt-get install software-properties-common
sudo apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xcbcb082a1bb943db
sudo add-apt-repository 'deb [arch=amd64,i386] http://mirror.jmu.edu/pub/mariadb/repo/10.1/ubuntu trusty main'
sudo apt-get update
sudo apt-get install mariadb-server

#command line client, also need for python lib
sudo apt-get install mysql-client

###################################################################
# phpmyadmin (optional), make sure its not on port 80
###################################################################
sudo apt-get install php5 libapache2-mod-php5 php5-mcrypt

vim /etc/apache2/mods-enabled/dir.conf

#move index.php to front of list
<IfModule mod_dir.c>
    DirectoryIndex index.php index.html index.cgi index.pl index.xhtml index.htm
</IfModule>

sudo service apache2 restart

sudo apt-get update
sudo apt-get install phpmyadmin

sudo php5enmod mcrypt
sudo service apache2 restart

###################################################################
# Install pip
###################################################################

#for python 3.4
cd ~
wget https://bootstrap.pypa.io/get-pip.py
python3.4 get-pip.py
rm get-pip.py

###################################################################
# Python modules
###################################################################

python3.4 -m pip install flask #flask
python3.4 -m pip install Flask-WTF #flask forms
python3.4 -m pip install flask-compress #flask gzip compression extension
python3.4 -m pip install requests #requests
python3.4 -m pip install elasticsearch
python3.4 -m pip install PyMySQL

###################################################################
# Configuration
###################################################################

###########################################
#/etc/apache2/sites-enabled/actortrackr.com.conf

<VirtualHost *:80>
    ServerAdmin ctig@lookingglasscyber.com
    DocumentRoot /var/www/actortrackr.com
    ServerName actortrackr.com
    ServerAlias www.actortrackr.com
    RewriteEngine On
    RewriteOptions inherit
    CustomLog /var/log/apache2/actortrackr.com.log combined
    Options -Indexes

    WSGIScriptAlias         /       /var/www/actortrackr.com/actor.wsgi

    <Directory /var/www/actortrackr.com>
        Require         all     granted
        WSGIScriptReloading On
    </Directory>

    <Location />
        LimitRequestBody 52428800
    </Location>

</VirtualHost>

###########################################
#/etc/apache2/ports.conf

#where phpmyadmin is running
Listen 8080


###################################################################
# Start Server, hit some pages, and check for errors
###################################################################
clear; service apache2 restart; tail -f /var/log/apache2/error.log

