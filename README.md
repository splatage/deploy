<pre>
# deploy
Minecraft Server Management Interface

Requirements:
* Linux
* screen
* perl
* rsync
* mojolicous
* yancy
* mysql/mariadb
* OpenSSH + key auth

Perl modules:
  cpan install Mojolicious
  cpan install Mojolicious::Plugin::Config 
  cpan install Mojolicious::Plugin::Authentication
  cpan install DBD::mysql
  cpan install Mojo::mysql
  cpan install IO::Socket::SSL
  cpan install Log::Log4perl
  cpan install Crypt::PBKDF2
  cpan install Mojolicious::Plugin::AutoReload
  cpan install Mojolicious::Plugin::Yancy
  cpan install Yancy::Plugin::Auth::Password 
  cpan install Digest::Bcrypt
  cpan install Mojo::AsyncAwait
  cpan install Future::AsyncAwait
  cpan install MCE::Loop
  cpan install MCE::Shared

  
  
Connectivity:
  The deploy user needs SSH key access to the filestore and user@nodes.
  The filestore user also needs have SSH key access to all user and node combinations
  Insure SSH key authentication is configured between user@deploy => all user@nodes, and file store user@host => user@nodes

Nginx:
  Use reverse proxy with authentication for an additional layer of protection
  
Fail2ban:
  Can tie with nginx to block password failures if using additional nginx auth
  
</pre>
