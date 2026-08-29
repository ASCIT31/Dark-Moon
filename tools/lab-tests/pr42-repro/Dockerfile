FROM php:8.2-apache
RUN a2enmod rewrite && sed -i 's/Options Indexes FollowSymLinks/Options +Indexes +FollowSymLinks/' /etc/apache2/apache2.conf \
 && printf '<Directory /var/www/html>\n  Options +Indexes\n  AllowOverride All\n  Require all granted\n</Directory>\n' >> /etc/apache2/apache2.conf
COPY www/ /var/www/html/
RUN chmod -R 755 /var/www/html
