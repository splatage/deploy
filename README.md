# deploy
Minecraft Server Management Interface<br/>
<br/>
Requirements:<br/>
* Linux<br/>
* screen<br/>
* perl<br/>
* rsync<br/>
* mojolicous<br/>
* yancy<br/>
* mysql/mariadb<br/>
* OpenSSH<br/>

Perl modules:
  cpan install Mojolicious::Plugin::Authentication
  cpan install IO::Socket::SSL
  cpan install Log::Log4perl
  cpan install Crypt::PBKDF2
  cpan install Mojolicious::Plugin::AutoReload
  cpan install Mojolicious::Plugin::Yancy
  cpan install Yancy::Plugin::Auth::Password 
  cpan install Digest::Bcrypt

Connectivity:
  The deploy user needs SSH key access to the filestore and user@nodes.
  The filestore user also needs have SSH key access to all user and node combinations
  Insure SSH key authentication is configured between user@deploy => all user@nodes, and file store user@host => user@nodes
