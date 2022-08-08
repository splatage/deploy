#!/usr/bin/perl

use Net::OpenSSH;
use DBD::mysql;
use DBI;
use Carp         qw( croak );
use Data::Dumper qw(Dumper);
use POSIX qw(strftime);
use Time::Piece;
use Time::Seconds;

 
# use strict;
# use warnings;

#use Time::Local qw( timelocal_posix timegm_posix );
# use Modern::Perl

use Log::Log4perl;

###########################################################
##         Declare Variables for Global Scope            ##
###########################################################

my $db_host;            # From config file
my $db_user;            # From config file
my $db_pass;            # From config file
my $db_name;            # From config file
my $dbh;                # DataBase Handle
my $sth;                # DB Syntax Handle
my $ref;                # HASH reference for DB results
my %settings;           # HASH storing the DB settings
my %game_settings;      # HASH storing DB gamesettings
my %global_settings;    # Hash storing global variables
my %node_settings;      # HASH sotring nodes from DB
my %ssh_connections;    # HASH Storing ssh connections
my @enabled_games;      # 
my @disabled_games;     #
my @enabled_nodes;      #
my @disabled_nodes;     #
my %online_games;       #
my $online_nodes;       #
my $log_conf;           #
my @gateway_name;
my $gatewayName;


my $debug = false;    # Print out settings returned from DB

###########################################################
##   Database Connection                                 ##
###########################################################

read_config_file('deploy.cfg');
$dbh = DBI->connect( "DBI:mysql:database=$db_name;host=$db_host",
       "$db_user", "$db_pass", { 'RaiseError' => 1 } );

###########################################################
##             Logging Configuration                     ##
###########################################################

configLogger();
Log::Log4perl::init( \$log_conf );

my $log = Log::Log4perl::get_logger();
   $log->info("Hello! Starting...");


###########################################################
##                      MAIN                             ##
###########################################################

my $delay = 60;
my $time  = $delay;
                  # Time period for main loop in seconds
while(){main()};  # Start endless main loop
#main();          # if a process takes longer this allows
                  # us to gracefully drop a time loop
                  # rather than coliding tasks

sub main {

    syncTime($delay);

    $time = time();
    $log->info("Waking up");
    
    refreshDB();

###########################################################
##            Sync Data from DataBase                    ##
###########################################################
    %{$global_settings} = ();
    %{$game_settings}   = ();
    %{$node_settings}   = ();

    fetch_settings_from_db->( global_settings, var_name );
    fetch_settings_from_db->( game_servers,    gs_name );
    fetch_settings_from_db->( nodes,           node_name );

    debug->( %global_settings );
    debug->( %node_settings );
    debug->( %game_settings );

   
   # Clear out varables and fetch them from the DB
   # The DB is to connection point that allows us to 
   # be modular...web api will update values, to
   # be retrived here
   
    @enabled_games=();
    @disabled_games=();
    @enabled_nodes=();
    @disabled_nodes=();
    @online_games=();
    @online_nodes=();

    get_game_settings_key_value->(
        \%game_settings, 'enabled', '1', \@enabled_games
    );
    get_game_settings_key_value->(
        \%game_settings, 'enabled', '0', \@disabled_games
    );
    get_node_settings_key_value->(
        \%node_settings, 'enabled', '1', \@enabled_nodes
    );
    get_node_settings_key_value->(
        \%node_settings, 'enabled', '0', \@disabled_nodes
    );
    get_game_settings_key_value->(
        \%game_settings, 'isBungee', '1', \@gateway_name
    );
 
    @gateway_name[0] or die "[!!] FATAL: isBungee is not set. You must specify the bungecord server"; 
    $gatewayName = @gateway_name[0];
    
    
  # Clear and repopulate the temp table
    clear_isOnline_table();

    foreach my $node (@enabled_nodes) { fill_isOnline_table($node) }

    pruneList();

    bootList();

    return 0;
}


sub pruneList {

    $log->debug("Generating list of game instances to prune");

    my %prune_list;

   # Find game servers that are running but not marked as enabled
    my  $query = "select t1.gs_name, t2.ip from game_servers t1 LEFT JOIN ";
        $query .= "isOnline t2 ON t1.gs_name = t2.gs_name WHERE ";
        $query .= "t2.online = 1 AND t1.enabled = 0;";

    my  $sth = $dbh->prepare("$query");
        $sth->execute();

     $log->trace("$query");

    while ( $ref = $sth->fetchrow_hashref ) {
            $prune_list{ $ref->{gs_name} } = $ref->{ip};
            $log->info("[!!] Marked to HALT: $ref->{gs_name} $ref->{ip}");
    }

    ## Running but on the wrong machine. Shut down to migrate
    my  $query = "select t1.gs_name, t2.ip from game_servers t1 LEFT JOIN ";
        $query .= "isOnline t2 ON t1.gs_name = t2.gs_name WHERE ";
        $query .= "t1.node_host != t2.ip;";

    my  $sth = $dbh->prepare("$query");
        $sth->execute();

    $log->trace("$query");

    while ( $ref = $sth->fetchrow_hashref ) {
            $prune_list{ $ref->{gs_name} } = $ref->{ip};
            $log->info("[!!] Marked to migrate: $ref->{gs_name} $ref->{ip} => $game_settings{$ref->{gs_name}}{node_host}"
        );
    }

    #############################
    ### ShutDown ################
    #############################

    keys %prune_list;
    while ( my ( $n, $ip ) = each %prune_list ) {
            sendCommand( "say Server is closing in 10 seconds", $n );   
    }
    
    sleep(5);
    
    keys %prune_list;
    while ( my ( $n, $ip ) = each %prune_list ) {
        haltGame( $n, $ip );
    }
    
    
#    keys %prune_list;
#    while ( my ( $n, $ip ) = each %prune_list ) {
#        haltGame( $n, $ip );
#    }
    
    
    
    $log->debug("Nothing to do") if not (%prune_list);
}


sub bootList {

    $log->debug("Generating list of game instances to boot");

    my %boot_list;

  # Find games off-line but marked as enabled
    my $query  = "select t1.gs_name, t1.node_host from game_servers t1 LEFT JOIN ";
       $query .= "isOnline t2 ON t1.gs_name = t2.gs_name ";
       $query .= "WHERE t2.ip IS NULL AND t1.enabled = 1";

    my $sth = $dbh->prepare("$query");
       $sth->execute();

       $log->trace("$query");

    while ( $ref = $sth->fetchrow_hashref ) {
        $boot_list{ $ref->{gs_name} } = $ref->{node_host};
        $log->debug("Found $ref->{gs_name} $ref->{node_host}");
    }

    keys %boot_list;
    while ( my ( $n, $ip ) = each %boot_list ) {
        $log->info("Booting: $n $ip");

        deployGame($n);
        bootGame($n);
        registerGame($n);
    }
    
    
    $log->debug("Nothing to do") if not (%boot_list);
}



#########################################################
##               Main Utility Functions                ##
#########################################################

sub registerGame {

   ## TODO: read the name gateway server from the settings table, and use bungee as default
   ## Requires the bungeeservermanager plugin
   ## https://www.spigotmc.org/resources/bungeeservermanager-bungeecord-mysql.24837/
   
    my ($name) = @_[0];


    $log->info("Registering $name on the network");

    ( $islobby = true )       if     $game_settings{$name}{'is_lobby'};
    ( $islobby = false )      if not $game_settings{$name}{'is_lobby'};

    ( $isrestricted = true )  if     $game_settings{$name}{'is_restricted'};
    ( $isrestricted = false ) if not $game_settings{$name}{'is_restricted'};

    my $cmd;
       $cmd = "servermanager delete " . $name;

    sendCommand( "$cmd", $gatewayName );

    $cmd  = "servermanager add " . $name . " ";
    $cmd .= $game_settings{$name}{'node_host'} . " ";
    $cmd .= $game_settings{$name}{'port'} . " ";
    $cmd .= ${islobby} . " true ";
    $cmd .= $isrestricted . " " . $name;

    sendCommand( "$cmd", $gatewayName );

    return 0;
}

sub deregisterGame {

    my $name = @_[0];
    my $cmd = "servermanager delete " . $name;
    #my $name = $gatewayName;
       $log->debug("Deregistering $name from the network");
       
    sendCommand( "$cmd", $gatewayName );

}

sub sendCommand {
    ## TODO: Read the correct credentials from the DB
    
    my ( $this_cmd, $gs_name ) = @_;
    my @results;
    my $ip = $online_games{$gs_name};
    
     $log->debug("Sending command: $this_cmd to $gs_name");

    connectSSH( 'minecraft', $ip );
     $log->debug("SSH: $ssh_connection minecraft $ip");

   # %ssh_connections{} is declared globally
    my $ssh_connection = $ssh_connections{$ip};    
       $ssh_connection->system("screen -p 0 -S $gs_name -X clear");
       $ssh_connection->system("screen -p 0 -S $gs_name -X hardcopy");
       $ssh_connection->system("screen -p 0 -S $gs_name -X eval 'stuff \"" . $this_cmd . "\"^M'" );
       
     $log->trace( "\[$ip\] $gs_name: screen -p 0 -S $gs_name -X eval 'stuff \"" 
          . $this_cmd
          . "\"^M'" );
          
     Time::HiRes::sleep( 0.05 );
    
    $ssh_connection->system("screen -p 0 -S $gs_name -X hardcopy");
    $results = $ssh_connection->capture("cat $gs_name/game_files/hardcopy.0");

    my @results = split( '\n', $results );
    @results =~ /\S/, @results;
    $results =~ s/[^[:ascii:]]//g, $results;
    foreach (@results) {
        $log->debug("$_");
    }
    
    return $results;
}


sub fetch_settings_from_db {

    my ( $table, $index_column ) = @_;
     $log->debug("Reading DB table: $table");

    $sth = $dbh->prepare("SELECT * FROM $table");
    $sth->execute();

    while ( $ref = $sth->fetchrow_hashref() ) {
        my $index_name = $ref->{$index_column};

        foreach ( @{ $sth->{NAME} } ) {
            my $var_name  = $_;
            my $var_value = $ref->{$var_name};

            if ( $table eq 'global_settings' ) {
                $global_settings{$index_name}{$var_name} = $var_value;
            }

            if ( $table eq 'nodes' ) {
                $node_settings{$index_name}{$var_name} = $var_value;
            }

            if ( $table eq 'game_servers' ) {
                $game_settings{$index_name}{$var_name} = $var_value;
            }
        }
    }

    

}

sub debug {
    my (%hash) = @_;
    if ( $debug eq 'true' ) {
        warn "debug is enabled";
        print "----------------\n";
        print Dumper \%hash;
        print "----------------\n";
    }
}


sub syncTime {
    my $period = @_[0];
   
    $log->debug("Going back to sleep");
    
    while ( ( $time % $period ) != 0 ) {
        $time = time();
        sleep(1);
    }
}


sub refreshDB {
    ## TODO: Handle any errors correctly
    
    unless ( $dbh->ping ) {
        $log->info("No connection to DB...reconnecting");
        $dbh = DBI->connect( "DBI:mysql:database=$db_name;host=$db_host",
            "$db_user", "$db_pass", { 'RaiseError' => 1 } );
    }
    
    return 0;
}

sub read_config_file {
    my ($configfile) = @_[0];

    open( CONFIG, '<', $configfile ) or croak "[!!] $configfile doesn't exist";

    while (<CONFIG>) {
        chomp;                 # no newline
        s/#.*//;               # no comments
        s/^\s+//;              # no leading white
        s/\s+$//;              # no trailing white
        next unless length;    # anything left?
        ( $var, $value ) = split( /\s*=\s*/, $_, 2 );
        $User_Preferences{$var} = $value;
    }

    close(CONFIG);

    $db_host = $User_Preferences{'db_host'};
    $db_user = $User_Preferences{'db_user'};
    $db_pass = $User_Preferences{'db_pass'};
    $db_name = $User_Preferences{'db_name'};
}


sub get_game_settings_key_value {
    ## Search settings hashs and populate specified array
    
    my ( $hash_ref, $key, $value, $array_ref ) = @_;
     $log->debug("Reading gameserver $key $value from DB");

    foreach my $object ( sort keys %{$hash_ref} ) {
        foreach my $variable ( keys %{ $game_settings{$object} } ) {
            if ( $variable eq $key ) {
                if ( $game_settings{$object}{$variable} eq $value ) {
                    push @{$array_ref}, $object;
                }
            }
        }
    }
}


sub get_node_settings_key_value {
    ## Search settings hashs and populate specified array
    
    my ( $hash_ref, $key, $value, $array_ref ) = @_;
     $log->debug("Reading node $key $value from DB");

    foreach my $object ( sort keys %{$hash_ref} ) {
        foreach my $variable ( keys %{ $node_settings{$object} } ) {
            if ( $variable eq $key ) {
                if ( $node_settings{$object}{$variable} eq $value ) {
                    push @{$array_ref}, $object;
                }
            }
        }
    }
}


sub connectSSH {
    ## Takes username and ip, and confirms/creates a SSH connection
    ## Stores the connection in the global %ssh_connections{}
    
    my ( $credentials, $ip ) = @_;
    
    if ($ssh_connections{$ip}) {
        $ssh_connections{$ip}->check_master;
        $log->debug("SSH $credentials\@$ip is healthy");
    }
    
    else {
        $log->info("New SSH: $credentials\@$ip");

        my $this_connection;
        my $connection = $credentials . "@" . $ip;
        
        $this_connection = Net::OpenSSH->new($connection);
         my $error = $this_connection->error;

        $log->warn("$ip: $error") if $this_connection->error;

        $ssh_connections{$ip} = $this_connection;
    }
}


sub clear_isOnline_table {

    $log->debug("Clearing isOnline table");
    
    my $sth = $dbh->prepare("DROP TABLE IF EXISTS isOnline;");
              $sth->execute();
              

    my $new_table  = 'CREATE TABLE isOnline ';
       $new_table .= '( id int(9) NOT NULL AUTO_INCREMENT, node VARCHAR(255) NOT NULL, ';
       $new_table .= 'checked TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, gs_name VARCHAR(255) NOT NULL, ';
       $new_table .= 'ip VARCHAR(16) NOT NULL, online TINYINT(1) NOT NULL, mem INT NOT NULL, ';
       $new_table .= 'cpu INT NOT NULL, UNIQUE KEY `id` (`id`)) ENGINE=InnoDB;';

    $sth = $dbh->prepare("$new_table");
           $sth->execute();


    $insert = 'UPDATE game_servers SET online = 0, cpu = NULL, mem = NULL;';
    
    $sth = $dbh->prepare($insert);
           $sth->execute();
 
}


sub rotateLogTables {
    ## TODO: Add stats logging to DB for webapp...
}


sub fill_isOnline_table {

    my ($this_node) = @_;
    my $this_ip = $node_settings{$this_node}{ip};

    $log->debug("Games on $this_node \[$this_ip\]");

    connectSSH( 'minecraft', $node_settings{$this_node}{ip} ) or next;

    my $procs   = $ssh_connections{$this_ip}->capture("screen -list");
    my @screens = split( '\n', $procs );
       @screens = grep /[0-9]+\.[a-zA-Z0-9]/, @screens;


    foreach my $line (@screens) {
 
        my @columns = split( /\s/, $line );
        
        my ( $screenpid, $screenname ) = split( /\./, @columns[1] );
        my @info;
        
        $game_settings{$screenname} or next;
        $online_games{$screenname} = $this_ip;
        
        

          
        my $insert;
        my $epoch_time = time();

        my @proc = split( ' ',
            $ssh_connections{$this_ip}->capture("ps --no-headers --ppid $screenpid -o %cpu,rss") );
            @proc[1] = int( @proc[1] / 1024 );


         my $screen_log;
         
         if ( $screenname eq $gatewayName ) {
            $screen_log .= sendCommand( "glist",    $screenname );
         }
         else {
            $screen_log  = sendCommand( "minecraft:time query gametime^Mversion^Mmemory^M",  $screenname );
         }

         my $plugins      = $game_settings{$screenname}{'node_path'} . "/";
            $plugins     .= $screenname . "/game_files/plugins/";
            $screen_log  .= "Plugins:\n" . $ssh_connections{$this_ip}->capture("cd $plugins; ls *jar");

         foreach my $result ( split('\n', $screen_log ) ) {
            if ( $result !~ m/command/i ) {
                 $result =~ s/^\[[^\]]+]:/> /;
                 $result =~ s/^/<div>/;
                 $result =~ s/$/<\/div>/;
                 push @info, $result;
                   $log->trace("$result");
             }
            if ( $result =~ m/The time is / ) {
                 $result =~ s/[^0-9]//g;
                 $result = $result / 20;
                 $result = Time::Seconds->new($result);
                 $result = $result->pretty;
                 push @info, "Server online for $result!";
                   $log->trace("$result");
            }
         }

        $result = join( '', @info );

        $log->debug("\[$screenpid\] $screenname \t@proc[0]%\t@proc[1]M ");

        $insert  = "INSERT INTO isOnline ( node, checked, online, gs_name, ip, cpu, mem ) ";
        $insert .= "values ('$this_node', FROM_UNIXTIME('$epoch_time')";
        $insert .= ", '1', '$screenname', '$this_ip', '@proc[0]', '@proc[1]')";

        
       refreshDB();
        my $sth = $dbh->prepare($insert);
           $sth->execute();
        

        $insert  = "UPDATE game_servers SET cpu = '@proc[0]', mem = '@proc[1]', info = '$result' ";
        $insert .= "WHERE gs_name = '$screenname';";

        
       refreshDB();
        my $sth = $dbh->prepare($insert);
           $sth->execute();
        

    };
 
    
    $insert  = "UPDATE game_servers INNER JOIN ";
    $insert .= "isOnline ON game_servers.gs_name = ";
    $insert .= "isOnline.gs_name SET game_servers.online = isOnline.online;";
    
    $log->trace("$insert");
    
    refreshDB();
    my $sth = $dbh->prepare($insert);
       $sth->execute();
    
}


sub haltGame {
    my ( $this_game, $ip ) = @_;

    $log->info("Halting: $this_game $ip");

    sendCommand( "servermanager kick $this_game^Mco purge t:90d", $gatewayName );
    deregisterGame($this_game);
#    sendCommand( "co purge t:90d", $this_game );
    sleep(2);

    storeGame($this_game);
    sendCommand( "stop^Mend", $this_game );
#    sendCommand( "end",  $this_game );
    sleep(1);

    return 0;
}

sub configLogger {

    $log_conf = q{
        log4perl.category                  = DEBUG, Logfile, Screen, DBAppndr

 
        log4perl.appender.Logfile          = Log::Log4perl::Appender::File
        log4perl.appender.Logfile.filename = deploy.log
        log4perl.appender.Logfile.layout   = Log::Log4perl::Layout::PatternLayout
        log4perl.appender.Logfile.layout.ConversionPattern = [%r|%R]ms %p %L %m %T%n 
 
        log4perl.appender.Screen         = Log::Log4perl::Appender::Screen
        log4perl.appender.Screen.stderr  = 0
        log4perl.appender.Screen.layout = Log::Log4perl::Layout::SimpleLayout
  
        log4perl.appender.DBAppndr            = Log::Log4perl::Appender::DBI
    };

    $log_conf .=
      "log4perl.appender.DBAppndr.datasource = DBI:mysql:database=$db_name\n";
    $log_conf .= "mc_control;host=$db_host;port=3306\n";
    $log_conf .= "log4perl.appender.DBAppndr.username   = $db_user\n";
    $log_conf .= "log4perl.appender.DBAppndr.password   = $db_pass\n";

    $log_conf .= q{
        log4perl.appender.DBAppndr.sql        = \
        INSERT INTO logFile                \
            (date, loglevel, message) \
            VALUES (?,?,?)

        log4perl.appender.DBAppndr.params.1 = %d
        log4perl.appender.DBAppndr.params.2 = %p  
        log4perl.appender.DBAppndr.layout    = Log::Log4perl::Layout::NoopLayout
        log4perl.appender.DBAppndr.warp_message = 0
        log4perl.appender.DBAppndr.usePreparedStmt = 1
    };
}

sub storeGame {
    ## Store - pull files from node to storage
    ## Rsync cannot move files between two remote locations
    ## This requires we login to one, and execute rsync
    ## as a local process. For Security the $store_host is used
    ## providing a firewall in effect
    
    my ($gs_name) = @_;
    
    ## Store - Pull files from node back to storage
    my $sip      = $game_settings{$gs_name}{"store_host"};
    my $susr     = $game_settings{$gs_name}{"store_usr"};
    my $cp_to    = $game_settings{$gs_name}{"store_path"} . "/";

    my $cp_from  = $game_settings{$gs_name}{"node_usr"} . "@";
       $cp_from .= $online_games{$gs_name} . ":";
       $cp_from .= $game_settings{$gs_name}{"node_path"} . "/" . $gs_name;

    $log->info("Storing: $gs_name as $susr\@$sip");
    $log->debug(" $cp_from $cp_to ");
    
    connectSSH( $susr, $sip );

    sendCommand( "say Backup in progress. Server going readonly...", $gs_name );
    sendCommand( "save-off",                                         $gs_name );
    sendCommand( "save-all",                                         $gs_name );

    sleep(2);

    $log->debug("rsync -auv --delete --exclude='*jar' -e 'ssh -o StrictHostKeyChecking=no' $cp_from $cp_to");
    $ssh_connections{$sip}->system("rsync -auv --delete --exclude='*jar' -e 'ssh -o StrictHostKeyChecking=no' $cp_from $cp_to");

    sendCommand( "save-on",             $gs_name );
    sendCommand( "say Backup finished", $gs_name );

    return 0;
}

sub bootGame {

    my $gs_name = @_[0];
    
    $log->info("Booting: $gs_name");

    my $usr = $game_settings{$gs_name}{"node_usr"};
    my $ip  = $game_settings{$gs_name}{"node_host"};
    my $bin = $game_settings{$gs_name}{"server_bin"};

    my $invocation;
       $invocation  = "cd " . $game_settings{$gs_name}{'node_path'};
       $invocation .= "/" . $gs_name . "/game_files";
       $invocation .= " && screen -h 1024 -L -dmS " . $gs_name;
       $invocation .= " " . $game_settings{$gs_name}{'java_bin'};
       $invocation .= " -Xms" . $game_settings{$gs_name}{'mem_min'} . "M";
       $invocation .= " -Xmx" . $game_settings{$gs_name}{'mem_max'} . "M";
       $invocation .= " " . $game_settings{$gs_name}{'java_flags'};
       $invocation .= " -jar " . $game_settings{$gs_name}{'server_bin'};
       $invocation .= " --forceUpgrade";
       $invocation .= " --port " . $game_settings{$gs_name}{'port'};
       $invocation .= " nogui server";
       $invocation =~ s/\n+/ /g;

    $log->trace("$invocation");

    connectSSH( $usr, $ip );
    $ssh_connections{$ip}->system("$invocation");

    sleep(10);

    my $screen = $ssh_connections{$ip}->capture("screen -list");
    
    if ( !grep /$gs_name/i, $screen ) {
    
        $log->warn("!! Server failed to boot !!");
        
        my $screen_log  = $game_settings{$gs_name}{'node_path'} . "/";
           $screen_log .= $gs_name . "/game_files/screenlog.0";
        my $failed      = $ssh_connections{$ip}->capture("tail $screen_log");

        @results = split( /\n/, $failed );
        foreach (@results) {
            $log->warn("$_");
        }
        return 1;
    }
    else {
    
     my $epoch_time = time();
     my $insert  = "INSERT INTO isOnline ( node, checked, online, gs_name, ip, cpu, mem ) ";
        $insert .= "values ('$ip', FROM_UNIXTIME('$epoch_time')";
        $insert .= ", '1', '$gs_name', '$ip', '0', '0') ON DUPLICATE KEY UPDATE gs_name='$gs_name' ";

     $log->info("boot sql: $insert");
        
       refreshDB();
        my $sth = $dbh->prepare($insert);
           $sth->execute();
        
    #INSERT INTO table (id, name, age) VALUES(1, "A", 19) ON DUPLICATE KEY UPDATE name="A", age=19
    }
    return 0;
}


sub deployGame {
    ## Deploy - push file from storage to node
    ## Rsync cannot move files between two remote locations
    ## This requires we login to one, and execute rsync
    ## as a local process
    
    my ($gs_name) = @_;
    my $ip = $online_games{$gs_name};

    $log->info("deployGamerserver: $gs_name");

    my $usr     = $game_settings{$gs_name}{"node_usr"};
    my $ip      = $game_settings{$gs_name}{"node_host"};

    my $susr    = $game_settings{$gs_name}{"store_usr"};
    my $sip     = $game_settings{$gs_name}{"store_host"};

    my $cp_to   = $usr . "@" . $game_settings{$gs_name}{"node_host"} . ":";
       $cp_to  .= $game_settings{$gs_name}{"node_path"} . "/";

    my $cp_from = $game_settings{$gs_name}{"store_path"} . "/" . $gs_name;

    $log->trace(" $cp_from $cp_to ");

    connectSSH( $susr, $sip );
     $ssh_connections{$sip}->system("rsync -auv --delete -e 'ssh -o StrictHostKeyChecking=no' $cp_from $cp_to");
      
     $log->debug("rsync -auv --delete $cp_from $cp_to");

    return 0;
}


## Clean up any DB connections on exit
$sth->finish();
$dbh->disconnect();
