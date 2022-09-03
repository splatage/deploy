
use v5.28;
use Mojolicious::Lite -signatures;
use Mojo::AsyncAwait;
use Mojo::mysql;
use Mojolicious::Plugin::Authentication;
use Mojo::UserAgent;
use IO::Socket::SSL;
use Minion;
use Net::OpenSSH;
use DBD::mysql;
use DBI;
use Carp         qw( croak );
use Data::Dumper qw( Dumper );
use POSIX        qw( strftime );
use Time::Piece;
use Time::Seconds;
use Net::Ping;
use Log::Log4perl;
use Crypt::PBKDF2;
use File::Basename;
use lib dirname(__FILE__) . "/lib/Game";
use strict;
use warnings;

plugin 'AutoReload';

###########################################################
##         Declare Variables for Global Scope            ##
###########################################################

my $db_host;            # From config file
my $db_user;            # From config file
my $db_pass;            # From config file
my $db_name;            # From config file
my $sth;                # DB Syntax Handle
my $ref;                # HASH reference for DB results
my %settings;           # HASH storing the DB settings
my %User_Preferences;
my $users;
my %SSH_connections;    # HASH Storing ssh connections

my $DBgames   = {};
my %DBgames   = %$DBgames;
my $DBglobals = {};
my %DBglobals = %$DBglobals;
my $DBnodes   = {};
my %DBnodes   = %$DBnodes;

my $enabledGames;       #
my $disabledGames;      #
my $enabledNodes;       #
my $disabledNodes;      #

my %online_games;       #
my $online_nodes;       #
my $log_conf;           #
my @gateway_name;
my $gatewayName;

my $debug = 'false';    

###########################################################
##   Database Connection                                 ##
###########################################################

read_config_file('config/deploy.cfg');

my $dbh = DBI->connect( "DBI:mysql:database=$db_name;host=$db_host",
    "$db_user", "$db_pass", { 'RaiseError' => 1 } );

my $db_string =
  "mysql://" . $db_user . ":" . $db_pass . "@" . $db_host . "/" . $db_name;
my $db = Mojo::mysql->strict_mode($db_string);

plugin Minion => { mysql => "$db_string" };

## Logging

configLogger();
Log::Log4perl::init( \$log_conf );

my $log = Log::Log4perl::get_logger();
$log->info("Hello! Starting...");

###########################################################
##               Configure Yancy
###########################################################

plugin Yancy => {
    backend => { mysql => $db },

    # Read the schema configuration from the database
    read_schema => 1,
    schema      => {
        games => {

            # Show these columns in the Yancy editor
            'x-list-columns' =>
              [qw( name node release port mem_max store enabled isBungee )],
        },
        nodes => {
            'x-list-clomuns' => [qw( name ip enabled isGateway )],
        },

        gs_plugin_settings    => { 'x-hidden' => 'true' },
        global_settings       => { 'x-hidden' => 'true' },
        minion_jobs_depends   => { 'x-ignore' => 'true' },
        minion_workers_inbox  => { 'x-ignore' => 'true' },
        mojo_pubsub_subscribe => { 'x-ignore' => 'true' },
        isOnline              => { 'x-ignore' => 'true' },
        users                 => {
            'x-id-field' => 'email',
            required     => [ 'email', 'password' ],
            properties   => {
                email => {
                    type   => 'string',
                    format => 'email',
                },
                password => {
                    type   => 'string',
                    format => 'password',
                },
                is_admin => {
                    type    => 'boolean',
                    default => 0,
                },
            },
        },

    },
    editor => {
        require_user => { is_admin => 1 },
    },
};


###########################################################
##      Cron Backups
###########################################################

my $settings = readFromDB(
        table    => 'games',
        column   => 'name',
        hash_ref => 'true'
    );

foreach my $game (keys %{$settings}) {
    $log->info("scheduled backup for $game");
    $cron = $settings->{$game}{'crontab'} or $cron = '0 * * * *' ;
    plugin Cron => ( $game => {crontab => $cron, code => sub {
        app->minion->enqueue( store => [$game], { attempts => 1 } );
     } } );
}


###########################################################
##    Authentication
###########################################################
#app->renderer->cache->max_keys(0);
app->sessions->default_expiration( 1 * 60 * 60 );

my $salt = pack "C16", map { int( 128 * rand() ) } 0 .. 15;

app->yancy->plugin(
    'Auth::Password' => {
        schema          => 'users',
        allow_register  => 0,
        username_field  => 'email',
        password_field  => 'password',
        password_digest => {
            type => 'Bcrypt',
            cost => 12,
            salt => $salt,
        },
    }
);

group {
    my $route = under 'minion' => sub ($c) {
        my $name = $c->yancy->auth->current_user || '';
        if ( $name ne '' ) {
            return 1;
        }
        $c->res->headers->www_authenticate('Basic');
        return undef;
    };
    plugin 'Minion::Admin' => { route => $route };
};

under sub ($c) {

    # Authenticated
    my $name = $c->yancy->auth->current_user || '';
    if ( $name ne '' ) {
        return 1;
    }
    $c->render( template => 'login' );
    return;
};

###########################################################
##  Minion Routes
###########################################################

get '/update/:game/:node' => sub ($c) {

    my $task = 'update';
    my $game = $c->stash('game');
    my $node = $c->stash('node');

    # $c->minion->enqueue($task => [$game],{queue => $game});
    $c->minion->enqueue( $task => [$game], { attempts => 2 } );
    $c->flash( message => "sending minions to $task $game on $node " );
    $c->redirect_to("/node/$node");
};
app->minion->add_task(
    update => sub ( $job, $game ) {
        my $task = 'update';
        my $lock = $game;
        return $job->finish(
            "Previous job $task for $game is still active. Refusing to proceed")
          unless app->minion->lock( $lock, 1200 );

        $job->app->log->info("Job: $task $game begins");
        sleep 5;

        my $result = `hostname`;

        $job->app->log->info("$task $game completed");
        $job->finish(
            { message => "$task $game completed", output => $result } );
        app->minion->unlock($lock);
    }
);

## Boot   #################################################

get '/boot/:game/:node' => sub ($c) {

    my $task = 'boot';
    my $node = $c->stash('node');
    my $game = $c->stash('game');

    # $c->minion->enqueue($task => [$game],{queue => $game});
    $c->minion->enqueue( $task => [$game], { attempts => 1 } );

    $c->flash( message => "sending minions to $task $game on $node " );
    $c->redirect_to("/node/$node");
};
app->minion->add_task(
    boot => sub ( $job, $game ) {
        my $task = 'boot';
        my $lock = $game;
        return $job->finish(
            "Previous job $task for $game is still active. Refusing to proceed")
          unless app->minion->lock( $lock, 1200 );

        my $deploy = deployGame( game => $game );
        $job->note( deploy => $deploy );

        my $update = update( game => $game );
        $job->note( update => $update );

        my $boot = bootGame( game => $game, server_bin => $update );
        $job->note( boot => $boot );

        my $regist = registerGame( game => $game );
        $job->note( register => $regist );

        $job->app->log->info("$task $game completed");
        unless ($boot) {
            $job->finish( { message => "$task $game completed" } );
        }
        else {
            $job->fail( { message => "$task $game failed" } );
        }
        app->minion->unlock($lock);
    }
);

## Halt ###################################################

get '/halt/:game/:node' => sub ($c) {

    my $task = 'halt';
    my $node = $c->stash('node');
    my $game = $c->stash('game');

    # $c->minion->enqueue($task => [$game],{queue => $game});
    $c->minion->enqueue( $task => [$game], { attempts => 1 } );
    $c->flash( message => "sending minions to $task $game on $node " );
    $c->redirect_to("/node/$node");
};
app->minion->add_task(
    halt => sub ( $job, $game ) {
        my $task = 'halt';
        my $lock = $game;
        return $job->fail(
            "Previous job $task for $game is still active. Refusing to proceed")
          unless app->minion->lock( $lock, 60 );

        $job->app->log->info("Job: $task $game begins");

        my $store = storeGame( game => $game );
        $job->note( storegame => $store );
        my $halt = haltGame( game => $game );
        $job->note( halt => $halt );

        $job->app->log->info("$task $game completed");
        $job->finish( { message => "$task $game completed" } );

        app->minion->unlock($lock);
    }
);

## Deploy #################################################

get '/deploy/:game/:node' => sub ($c) {

    my $task = 'deploy';
    my $node = $c->stash('node');
    my $game = $c->stash('game');

    # $c->minion->enqueue($task => [$game],{queue => $game});
    $c->minion->enqueue( $task => [$game], { attempts => 2 } );
    $c->flash( message => "sending minions to $task $game on $node " );
    $c->redirect_to("/node/$node");
};
app->minion->add_task(
    deploy => sub ( $job, $game ) {
        my $task = 'deploy';
        my $lock = $game;
        return $job->finish(
            "Previous job $task for $game is still active. Refusing to proceed")
          unless app->minion->lock( $lock, 1200 );

        $job->app->log->info("Job: $task $game begins");

        my $output = deployGame( game => $game );

        $job->app->log->info("$task $game completed");
        $job->finish(
            { message => "$task $game completed", deploy => $output } );
        app->minion->unlock($lock);
    }
);

## Store #################################################

get '/store/:game/:node' => sub ($c) {

    my $task = 'store';
    my $node = $c->stash('node');
    my $game = $c->stash('game');

    # $c->minion->enqueue($task => [$game],{queue => $game});
    $c->minion->enqueue( $task => [$game], { attempts => 2 } );
    $c->flash( message => "sending minions to $task $game on $node " );
    $c->redirect_to("/node/$node");
};
app->minion->add_task(
    store => sub ( $job, $game ) {

        my $task = 'store';
        my $lock = $game;
        return $job->finish(
            "Previous job $task for $game is still active. Refusing to proceed")
          unless app->minion->lock( $lock, 1200 );

        $job->app->log->info("Job: $task $game begins");

        my $output = storeGame( game => $game );

        $job->app->log->info("$task $game completed");
        $job->finish(
            { message => "$task $game completed", store => $output } );
        app->minion->unlock($lock);
    }
);

## Link ###################################################

get '/link/:game/:node' => sub ($c) {

    my $task = 'link';
    my $node = $c->stash('node');
    my $game = $c->stash('game');

    # $c->minion->enqueue($task => [$game],{queue => $game});
    $c->minion->enqueue( $task => [$game], { attempts => 2 } );
    $c->flash( message => "sending minions to $task $game on $node " );
    $c->redirect_to("/node/$node");
};
app->minion->add_task(
    link => sub ( $job, $game ) {
        my $task = 'link';
        my $lock = $game;
        return $job->finish(
            "Previous job $task for $game is still active. Refusing to proceed")
          unless app->minion->lock( $lock, 10 );

        $job->app->log->info("Job: $task $game begins");

        my $regist = registerGame( game => $game );
        $job->note( register => $regist );

        $job->app->log->info("$task $game completed");
        $job->finish( { message => "$task $game completed" } );
        app->minion->unlock($lock);
    }
);

## Drop #################################################

get '/drop/:game/:node' => sub ($c) {

    my $task = 'drop';
    my $node = $c->stash('node');
    my $game = $c->stash('game');

    # $c->minion->enqueue($task => [$game],{queue => $game});
    $c->minion->enqueue( $task => [$game], { attempts => 2 } );
    $c->flash( message => "sending minions to $task $game on $node " );
    $c->redirect_to("/node/$node");
};
app->minion->add_task(
    drop => sub ( $job, $game ) {
        my $task = 'drop';
        my $lock = $game;
        return $job->finish(
            "Previous job $task for $game is still active. Refusing to proceed")
          unless app->minion->lock( $lock, 10 );

        $job->app->log->info("Job: $task $game begins");

        deregisterGame( game => $game );

        $job->app->log->info("$task $game completed");
        $job->finish( { message => "$task $game completed" } );
        app->minion->unlock($lock);
    }
);

###########################################################
##          Routing
###########################################################

get '/' => sub ($c) {
    #

    #
    my $results = checkIsOnline(
        list_by => 'node',
        node    => '',
        game    => ''
    );

    my $expected = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'enabled',
        value    => '1',
        hash_ref => 'true'
    );

    $c->stash(
        nodes    => $results,
        expected => $expected
    );

    $c->render( template => 'index' );
};

get '/log/:node/:game' => sub ($c) {

    my $game = $c->stash('game');
    my $node = $c->stash('node');

    my $results = readLog(
        node => $node,
        game => $game
    );

    $c->render(
        template => 'log',
        log_data => $results,
        node     => $node,
        game     => $game
    );
};

get '/info/:node/' => sub ($c) {

    my $node = $c->stash('node');

    my $results = infoNode( node => $node );

    $c->stash( results => $results );
    $c->render( template => 'node_details', results => $results );
};

get '/node/:node' => sub ($c) {

    my $node    = $c->stash('node');
    my $results = checkIsOnline(
        list_by => 'node',
        node    => $node,
        game    => ''
    );

    my $ip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $node,
        hash_ref => 'false'
    );

    my $expected = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'node',
        value    => $node,
        hash_ref => 'true'
    );

    my $jobs = app->minion->jobs(
        {
            queues => ['default'],
            states => [ 'active', 'locked' ],
            tasks  => [ 'boot',   'halt' ]
        }
    );

    $c->render(
        template => 'node',
        nodes    => $results,
        history  => $jobs,
        expected => $expected
    );
};

get '/files/:game' => sub ($c) {

    my $game    = $c->stash('game');
    my @results = getFiles( game => $game );

    $c->stash( files => @results );
    $c->render( template => 'files' );
};

get '/debug/:node/:game' => sub ($c) {

    my $node = $c->stash('node');
    my $game = $c->stash('node');
    my ( $results, $expected );

    my $is_configured = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'name',
        value    => $game,
        hash_ref => 'false'
    );

    my $jobs = app->minion->jobs(
        {
            queues => ['default'],
            states => [ 'active', 'locked' ],
            tasks  => [ 'boot',   'halt' ]
        }
    );

    $c->render(
        template => 'node',
        nodes    => $results,
        history  => $jobs,
        expected => $expected
    );
};

get '/move/:node/:game' => sub ($c) {

    my $node = $c->stash('node');
    my $game = $c->stash('node');
    my ( $results, $expected );

    my $is_configured = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'name',
        value    => $game,
        hash_ref => 'false'
    );

    my $jobs = app->minion->jobs(
        {
            queues => ['default'],
            states => [ 'active', 'locked' ],
            tasks  => [ 'boot',   'halt' ]
        }
    );

    $c->render(
        template => 'node',
        nodes    => $results,
        history  => $jobs,
        expected => $expected
    );
};

any '*' => sub ($c) {

    #$c->render(template => 'login') };
    $c->flash( error => "page doesn't exist" );
    $c->redirect_to("/");
};

###########################################################
##    Functions
###########################################################

# update(game => 'castaway');
sub update {
    my %args = (
        game    => '',
        node    => '',
        ip      => '',
        project => '',
        release => '',
        @_,    # argument pair list goes here
    );

    my ( $project, $release, $version );

    my $game = $args{'game'} or return 1;

    my $settings = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'name',
        value    => $game,
        hash_ref => 'true'
    );
    my $ip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $settings->{$game}{'node'},
        hash_ref => 'false'
    );

    if ( $settings->{$game}{isBungee} eq '1' ) {
        $project = 'waterfall';
    }
    else {
        $project = 'paper';
    }

    $release = $settings->{$game}{release};

    # Get latest release version
    my $project_url =
      "https://api.papermc.io/v2/projects/$project/versions/$release/";
    my $ua     = Mojo::UserAgent->new();
    my $builds = $ua->get($project_url)->result->json;

    my $latest    = $builds->{'builds'}[-1];
    my $file_name = "$project-$release-$latest.jar";

    $project_url = $project_url . '/builds/' . $latest;
    my $meta   = $ua->get("$project_url")->result->json;
    my $sha256 = $meta->{'downloads'}->{'application'}{'sha256'};

    my $path =
        $settings->{$game}{'node_path'} . '/'
      . $game
      . '/game_files/'
      . $file_name;

    # Install Latest version
    my $user = $settings->{$game}{'node_usr'};
    connectSSH( user => $user, ip => $ip );

    $project_url = $project_url . '/downloads/' . $file_name;
    my $cmd = 'wget -c ' . $project_url . ' -O ' . $path;

    print "connect: $user.$ip   $cmd\n";

    $SSH_connections{ $user . $ip }->system("$cmd");

    $cmd = "sha256sum $path";
    my @sha_file =
      split( / /, $SSH_connections{ $user . $ip }->capture("$cmd") );

    if ( $sha_file[0] eq $sha256 ) {
        return "$file_name SHA: $sha256";
    }
    else {
        return 0;
    }
}

sub readLog {
    my %args = (
        game => '',
        node => '',
        @_,    # argument pair list goes here
    );
    my $game = $args{'game'} or return 1;
    my $node = $args{'node'} or return 1;

    my $return_string;

    my $ip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $node,
        hash_ref => 'false'
    );

    if ( !$ip ) {
        my $warning = '<div class="alert alert-danger" role="alert">';
        $warning .= '!! WARNING !! <a href="/yancy#/nodes" class="alert-link">';
        $warning .= "$node is miss-configured in the nodes table in database";
        $warning .= '</a></div>';
        return $warning;
    }

    my $user = readFromDB(
        table    => 'games',
        column   => 'node_usr',
        field    => 'name',
        value    => $game,
        hash_ref => 'false'
    );

    if ( !$user ) {
        my $warning = '<div class="alert alert-danger" role="alert">';
        $warning .= '!! WARNING !! <a href="/yancy#/games" class="alert-link">';
        $warning .=
          "$game is miss-configured in the games_servers table in database";
        $warning .= '</a></div>';
        return $warning;
    }

    connectSSH( user => $user, ip => $ip );

    my $cmd = "[ -f ~/$game/game_files/screenlog.0 ] ";
    $cmd .= "&& tail -5000 ~/$game/game_files/screenlog.0 | tac | ";
    $cmd .= "sed '/Starting minecraft\\\|Enabled Waterfall/q' | tac";

    my $log = $SSH_connections{ $user . $ip }->capture("$cmd");
    $log =~ s/ /\&nbsp;/g;
    my @lines = split( /\n/, $log );

    foreach (@lines) {
        $return_string .=
          '<div style="width: 80rem;"><small>' . $_ . '</small></div>';
    }

    $return_string =~ s/\x1b[[()=][;?0-9]*[0-9A-Za-z]?//g;
    $return_string =~ s/\r//g;
    s/\007//g;
    $return_string =~ s/[^[:print:]]+//g;

    return $return_string;
}

sub readFromDB {

    refreshDB();

    my %args = (
        table    => '',
        column   => '',
        field    => '',
        value    => '',
        hash_ref => 'true',
        @_
    );

    return 1 if not $args{'table'};
    return 1 if not $args{'column'};

    my $table  = $args{'table'};
    my $column = $args{'column'};
    my $field  = $args{'field'};
    my $value  = $args{'value'};

    my ( $ref, $ref_name, $ref_value );
    my $result = {};
    my %result = %$result;

    $log->debug("sub readFromDB");

    my $select = '*';
    $select = $column if ( $args{'hash_ref'} eq 'false' );

    my $query = "SELECT $select FROM $table WHERE enabled = '1'";
    $log->debug("Reading DB table:");

    if ( $field ne '' && $value ne '' ) {
        $query .= " AND $field = '$value'";
    }

    $query .= ";";
    $log->debug("$query");

    $sth = $dbh->prepare($query);
    $sth->execute();

    while ( $ref = $sth->fetchrow_hashref() ) {
        my $index_name = $ref->{$column};

        foreach ( @{ $sth->{NAME} } ) {
            $ref_name                       = $_;
            $ref_value                      = $ref->{$ref_name};
            $result{$index_name}{$ref_name} = $ref_value;
        }
    }

    $sth->finish();

    if ( $args{'hash_ref'} eq 'true' ) {
        return \%result;
    }
    else {
        return $ref_value;
    }
}

# checkIsOnline();
sub checkIsOnline {

    my %args = (
        game    => '',
        node    => '',
        pid     => '',
        user    => 'minecraft',
        list_by => 'game',
        @_,    # argument pair list goes here
    );

    my $enabledNodes = readFromDB(
        table    => 'nodes',
        column   => 'name',
        field    => 'enabled',
        value    => '1',
        hash_ref => 'true'
    );

    my $enabledGames = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'enabled',
        value    => '1',
        hash_ref => 'true'
    );

    my %enabledNodes = %$enabledNodes;
    my @live_nodes;
    my @dead_nodes;
    my @nodes_to_check;
    my $temp_hash   = {};
    my %temp_hash   = %$temp_hash;
    my $return_hash = {};
    my %return_hash = %$return_hash;
    my $list_by     = $args{'list_by'};
    my $user        = $args{'user'};

    if ( $args{'node'} ) {
        @nodes_to_check = $args{'node'};
        $log->debug("Using specified node");
    }
    else {
        @nodes_to_check = ( sort keys %{$enabledNodes} );
        $log->debug("Using nodes from DB");
    }

    $log->debug("Pinging: \[@nodes_to_check\]");

    foreach my $this_node (@nodes_to_check) {

        #my %this_node = %$this_node;
        $log->debug("this node: $this_node");
        my $p = Net::Ping->new;
        if ( $p->ping( $enabledNodes{$this_node}{'ip'}, 0.01 ) ) {
            $log->debug("[OK] $this_node is online");
            push @live_nodes, $this_node;
        }
        else {
            $log->debug("[!!] $this_node is offline");
            push @dead_nodes, $this_node;
        }
    }
    $log->debug("Checking: \[@live_nodes\]");

    foreach my $this_node (@live_nodes) {
        $log->debug("Query $this_node for games...");

        my $ip = $enabledNodes{$this_node}{'ip'};

        if ( connectSSH( user => $user, ip => $ip ) ) {
            $return_hash{$this_node} = {};
            next;
        }

        $return_hash{$this_node} = {};

        my @cmd = "ps axo user:20,pid,ppid,pcpu,pmem,vsz,rss,cmd | grep -i ' [s]creen.*server\\|[j]ava.*server'";
        my $screen_list = $SSH_connections{ $user . $ip }->capture("@cmd");

        #        $log->debug("$screen_list");

        my @screen_list = split( '\n', $screen_list );

        foreach my $this_game (@screen_list) {
            my @column = split( / +/, $this_game );

            if ( $column[2] eq '1' ) {

                # SCREEN has ppid of 1. Load the PID and game
                $temp_hash{ $column[1] . $this_node }{'node'} = $this_node;
                $temp_hash{ $column[1] . $this_node }{'user'} = $column[0];
                $temp_hash{ $column[1] . $this_node }{'game'} = $column[12];
            }

            if ( $column[2] ne '1' ) {

                # Match java child ppid to SCREEN pid to reference correct hash
                $temp_hash{ $column[2] . $this_node }{'pid'}  = $column[1];
                $temp_hash{ $column[2] . $this_node }{'ppid'} = $column[2];
                $temp_hash{ $column[2] . $this_node }{'pcpu'} = $column[3];
                $temp_hash{ $column[2] . $this_node }{'pmem'} = $column[4];
                $temp_hash{ $column[2] . $this_node }{'vsz'}  = $column[5];
                $temp_hash{ $column[2] . $this_node }{'rss'}  = $column[6];
            }
        }
    }

    ## Remap temp_hash into return_hash based on $list_by arg
    #  Using list_by|game pair to avoind duplicates
    foreach my $result ( keys %temp_hash ) {
        my $list_by = $temp_hash{$result}{ $args{'list_by'} };

        my $game = $temp_hash{$result}{'game'};

        $log->warn("[!!] $game is running multiple times!")
          if ( $return_hash{$list_by}{$game} );

        $return_hash{$list_by}{$game}{'node'} = $temp_hash{$result}{'node'};
        $return_hash{$list_by}{$game}{'user'} = $temp_hash{$result}{'user'};
        $return_hash{$list_by}{$game}{'game'} = $temp_hash{$result}{'game'};
        $return_hash{$list_by}{$game}{'pid'}  = $temp_hash{$result}{'pid'};
        $return_hash{$list_by}{$game}{'ppid'} = $temp_hash{$result}{'ppid'};
        $return_hash{$list_by}{$game}{'pcpu'} = $temp_hash{$result}{'pcpu'};
        $return_hash{$list_by}{$game}{'pmem'} = $temp_hash{$result}{'pmem'};
        $return_hash{$list_by}{$game}{'vsz'}  = $temp_hash{$result}{'vsz'};
        $return_hash{$list_by}{$game}{'rss'}  = $temp_hash{$result}{'rss'};
    }

    ## Load the offline nodes
    foreach my $offline (@dead_nodes) {
        $return_hash{$offline}{'offline'}{'offline'} = 'true';
    }

    if ( $args{game} ) {

        if ( $return_hash{ $args{'game'} }{ $args{'game'} }{'node'} ) {
            $log->debug(
"Found $args{'game'} on $return_hash{ $args{'game'} }{ $args{'game'} }{'node'}"
            );
            return "$return_hash{ $args{'game'} }{ $args{'game'} }{'node'}";
        }

        else {
            return 0;
        }
    }

    return \%return_hash;
}

sub registerGame {

    my %args = (
        game => '',
        @_,    # argument pair list goes here
    );

    my $game = $args{'game'};
    my ( $islobby, $isrestricted, $cmd );

    my $settings = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'name',
        value    => $game,
        hash_ref => 'true'
    );

    my $gateway = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'isBungee',
        value    => '1',
        hash_ref => 'false'
    );

    my $node = readFromDB(
        table    => 'games',
        column   => 'node',
        field    => 'isBungee',
        value    => '1',
        hash_ref => 'false'
    );

    my $ip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $settings->{$game}{'node'},
        hash_ref => 'false'
    );

    # Exit if this game is a bungee server
    if ( $settings->{$game}{'isBungee'} eq '1' ) {
        return "This is a bungee instance, exiting";
    }

    $log->debug("Registering $game on the network with $gateway");

    $cmd = "servermanager delete " . $game . "^M";

    sendCommand( command => $cmd, game => $gateway, node => $node );
    sleep(0.5);

    if ( $settings->{$game}{'isLobby'} eq '1' ) {
        $islobby = 'true';
    }
    else {
        $islobby = 'false';
    }

    if ( $settings->{$game}{'isRestricted'} eq '1' ) {
        $isrestricted = 'true';
    }
    else {
        $isrestricted = 'false';
    }

    $cmd .= "servermanager add " . $game . " ";
    $cmd .= $ip . " ";
    $cmd .= $settings->{$game}{'port'} . " ";
    $cmd .= $islobby . " true ";
    $cmd .= $isrestricted . " " . $game;

    sendCommand( command => $cmd, game => $gateway, node => $node );
    sleep(0.5);

    return "$game linked to $gateway network - $cmd";
}

sub deregisterGame {
    my %args = (
        game => '',
        @_,    # argument pair list goes here
    );

    my $game = $args{'game'};
    my ( $islobby, $isrestricted, $cmd );

    my $settings = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'name',
        value    => $game,
        hash_ref => 'true'
    );

    my $gateway = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'isBungee',
        value    => '1',
        hash_ref => 'false'
    );

    my $node = readFromDB(
        table    => 'games',
        column   => 'node',
        field    => 'isBungee',
        value    => '1',
        hash_ref => 'false'
    );

    $log->debug("Registering $game on the network with $gateway");

    $cmd = "servermanager delete " . $game . "^M";

    sendCommand( command => $cmd, game => $gateway, node => $node );
}

# getFiles(game => 'benchmark');
sub getFiles {
    my %args = (
        user => '',
        ip   => '',
        game => '',
        @_,    # argument pair list goes here
    );

    my $game = $args{'game'};

    my $settings = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'name',
        value    => $game,
        hash_ref => 'true'
    );

    my %settings = %$settings;

    my $snode = $settings->{$game}{'store'};
    my $suser = $settings->{$game}{'store_usr'};
    my $spath = $settings->{$game}{'store_path'};

    my $sip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $snode,
        hash_ref => 'false'
    );

    my $results = {};
    my %results = %$results;

    return 1 if connectSSH( user => $suser, ip => $sip );

    # %SSH_connections{} is declared globally
    my $ssh_connection = $SSH_connections{ $suser . $sip };
    my @files = $ssh_connection->capture("cd $spath; find $game -type f ");
    chomp(@files);

    #    for (@files) {
    #        print "$_\n";
    #    }
    return \@files;
}

# s command => 'say hello', game => 'benchmark', node => '' );

sub sendCommand {
    my %args = (
        game    => '',
        command => '',
        node    => '',
        ip      => '',
        @_,
    );

    my $game    = $args{'game'};
    my $command = $args{'command'};
    my $node    = $args{'node'};

    my $settings = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'name',
        value    => $game,
        hash_ref => 'true'
    );

    # Order of prioroty for node:- commandline, then livegames then DB
    $node = checkIsOnline( list_by => 'node', node => '', game => $game )
      unless $node;
    $node = $settings->{$game}{'node'} unless $node;

    my $ip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $node,
        hash_ref => 'false'
    );

    my ( $results, @results );
    my $user = $settings->{$game}{'node_usr'};

    $log->debug("Sending command: $command to $game on $ip");

    connectSSH( user => $user, ip => $ip );   #or die "Error establishing SSH" ;

    # %SSH_connections{} is declared globally
    my $ssh_connection = $SSH_connections{ $user . $ip };

    $ssh_connection->system("screen -p 0 -S $game -X clear");
    $ssh_connection->system("screen -p 0 -S $game -X hardcopy");
    $ssh_connection->system(
        "screen -p 0 -S $game -X eval 'stuff \"" . $command . "\"^M'" );

    $log->debug( "\[$ip\] $game: screen -p 0 -S $game -X eval 'stuff \""
          . $command
          . "\"^M'" );

    Time::HiRes::sleep(0.05);

    $ssh_connection->system("screen -p 0 -S $game -X hardcopy");
    $results = $ssh_connection->capture("cat $game/game_files/hardcopy.0");

    @results = split( '\n', $results );
    $results = $results if /\S/;
    $results = $results if s/[^[:ascii:]]//g, $results;
    foreach (@results) {
        $log->debug("$game SCREEN: $_");
    }

    return $results;
}

sub refreshDB {
    unless ( $dbh->ping ) {
        $log->info("No connection to DB...reconnecting");
        $dbh = DBI->connect( "DBI:mysql:database=$db_name;host=$db_host",
            "$db_user", "$db_pass", { 'RaiseError' => 1 } );
    }

    return 0;
}

sub read_config_file {
    my ($configfile) = $_[0];

    my $CONFIG;
    open( $CONFIG, '<', $configfile ) or croak "[!!] $configfile doesn't exist";

    while (<$CONFIG>) {
        chomp;                 # no newline
        s/#.*//;               # no comments
        s/^\s+//;              # no leading white
        s/\s+$//;              # no trailing white
        next unless length;    # anything left?
        my ( $var, $value ) = split( /\s*=\s*/, $_, 2 );
        $User_Preferences{$var} = $value;
    }

    close($CONFIG);

    $db_host = $User_Preferences{'db_host'};
    $db_user = $User_Preferences{'db_user'};
    $db_pass = $User_Preferences{'db_pass'};
    $db_name = $User_Preferences{'db_name'};
}

sub connectSSH {
    ## Takes username and ip, and confirms/creates a SSH connection
    ## Stores the connection in the global %SSH_connections{}
    my %args = (
        user => '',
        ip   => '',
        @_,    # argument pair list goes here
    );

    $args{'user'} || return "Aborting SSH: must specify username";
    $args{'ip'}   || return "Aborting SSH: must specify ip";

    if ( $SSH_connections{ $args{'user'} . $args{'ip'} } ) {
        $SSH_connections{ $args{'user'} . $args{'ip'} }->check_master;
        $log->debug("SSH $args{'user'}\@$args{'ip'} is healthy");
        return 0;
    }

    else {
        $log->debug("New SSH: $args{'user'}\@$args{'ip'}");

        my $this_connection;
        my $connection = $args{'user'} . "@" . $args{'ip'};

        $this_connection = Net::OpenSSH->new( $connection,
            master_opts =>
              [ '-o PasswordAuthentication=no', '-o StrictHostKeyChecking=no' ]
        );

        if ( $this_connection->error ) {
            print "[!!] Error connecting to $args{'ip'}:";
            print $this_connection->error . "\n";

            # print Dumper $this_connection;

            return 1;
        }
        print "[OK] Connected to: $args{'user'}.$args{'ip'}";
        $SSH_connections{ $args{'user'} . $args{'ip'} } = $this_connection;

        return 0;
    }
}

# haltGame(game => 'benchmark');
sub haltGame {
    my %args = (
        game => '',
        node => '',
        @_,    # argument pair list goes here
    );

    my $game = $args{'game'};
    my $node = $args{'node'};

    $log->info("Halting: $game");

   #    sendCommand( "servermanager kick $game^Mco purge t:90d", $gatewayName );
   #    deregisterGame( game => $game );

    #    sleep(2);

    #    storeGame( game => $game );

    sendCommand( command => "stop^Mend", game => $game, node => $node );

    sleep(30);

    unless ( checkIsOnline( list_by => 'game', node => '', game => $game ) ) {
        $log->info("Halt $game succeeded");
        return "Halt $game succeeded";
    }
    else {
        $log->info("Failed to halt $game");
        return "Failed to halt $game";
    }
}

sub configLogger {

    $log_conf = q{
        log4perl.category                   = DEBUG, Logfile, Screen, DBAppndr

 
        log4perl.appender.Logfile           = Log::Log4perl::Appender::File
        log4perl.appender.Logfile.filename  = deploy.log
        log4perl.appender.Logfile.layout    = Log::Log4perl::Layout::PatternLayout
        log4perl.appender.Logfile.layout.ConversionPattern = [%r|%R]ms %p %L %m%n 
 
        log4perl.appender.Screen            = Log::Log4perl::Appender::Screen
        log4perl.appender.Screen.stderr     = 0
        log4perl.appender.Screen.layout    = Log::Log4perl::Layout::PatternLayout
        log4perl.appender.Screen.layout.ConversionPattern = [%r|%R]ms [%p]:%L %m%n 
  
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

# storeGame('benchmark');
sub storeGame {
    my %args = (
        game => '',
        @_,    # argument pair list goes here
    );

    my $game = $args{'game'};

    my ( $user, $suser, $cp_to, $cp_from );

    my $error = "Aborting task as $game is offline!! ";
    $error .= "It's potentially catastrophic to overwrite ";
    $error .= "the primary store with data we cannot verify. ";
    $error .= "Please ensure the game is running to prove viabitiy ";
    $error .= "before attempting a sync to the primary data store location";

    return $error
      unless ( checkIsOnline( list_by => 'game', node => '', game => $game ) );

    my $settings = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'name',
        value    => $game,
        hash_ref => 'true'
    );

    my %settings = %$settings;

    my $ip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $settings->{$game}{'node'},
        hash_ref => 'false'
    );

    my $sip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $settings->{$game}{'store'},
        hash_ref => 'false'
    );

    $log->info("deployGamerserver: $game");

    $user  = $settings{$game}{"node_usr"};
    $suser = $settings{$game}{"store_usr"};

    $cp_from = $user . "@" . $ip . ":";
    $cp_from .= $settings{$game}{"node_path"} . "/" . $game;

    $cp_to = $settings{$game}{"store_path"} . "/";

    $log->debug(" $cp_from $cp_to ");

    my $output = connectSSH( user => $suser, ip => $sip ) . "\n";

    $log->debug(
"rsync -auv --delete --exclude='plugins/*jar' -e 'ssh -o StrictHostKeyChecking=no -o BatchMode=yes' $cp_from $cp_to"
    );
    $output .=
      $SSH_connections{ $suser . $sip }->capture(
"rsync -auv --delete --exclude='pugins/*jar' -e 'ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o BatchMode=yes' $cp_from $cp_to"
      );

    return $output;
}

# bootGame('benchmark');
sub bootGame {
    my %args = (
        game       => '',
        server_bin => '',
        @_,    # argument pair list goes here
    );

    my $game = $args{'game'};

    my ( $user, $suser, $cp_to, $cp_from );

    return "$game is already online"
      if ( checkIsOnline( list_by => 'game', node => '', game => $game ) );

    my $settings = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'name',
        value    => $game,
        hash_ref => 'true'
    );

    my %settings = %$settings;

    my $ip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $settings->{$game}{'node'},
        hash_ref => 'false'
    );

    my $invocation;
    $invocation = "cd " . $settings->{$game}{'node_path'};
    $invocation .= "/" . $game . "/game_files";
    $invocation .= " && screen -h 1024 -L -dmS " . $game;
    $invocation .= " " . $settings->{$game}{'java_bin'};
    $invocation .= " -Xms" . $settings->{$game}{'mem_min'};
    $invocation .= " -Xmx" . $settings->{$game}{'mem_max'};
    $invocation .= " " . $settings->{$game}{'java_flags'};
    $invocation .= " -jar " . $args{'server_bin'};
    $invocation .= " --forceUpgrade";
    $invocation .= " --port " . $settings{$game}{'port'};
    $invocation .= " nogui server";
    $invocation =~ s/\n+/ /g;

    $log->trace("$invocation");
    $user = $settings->{$game}{'node_usr'};

    my $output = connectSSH( user => $user, ip => $ip );
    $SSH_connections{ $user . $ip }->system("$invocation");

    sleep(10);

    if ( checkIsOnline( list_by => 'game', node => '', game => $game ) ) {
        $log->info("Started $game");
        return 0;
    }
    else {
        $log->info("Failed to start $game");
        return 1;
    }
}

#deployGame('benchmark');
sub deployGame {
    my %args = (
        game => '',
        @_,    # argument pair list goes here
    );

    my $game = $args{'game'};

    my ( $user, $suser, $cp_to, $cp_from );

    my $error = "Aborting task as $game is currently online. ";
    $error .= "It would be unsafe to deloy overtop of a running game. ";

    return $error
      if ( checkIsOnline( list_by => 'game', node => '', game => $game ) );

    my $settings = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'name',
        value    => $game,
        hash_ref => 'true'
    );
    my %settings = %$settings;

    my $ip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $settings->{$game}{'node'},
        hash_ref => 'false'
    );

    my $sip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $settings->{$game}{'store'},
        hash_ref => 'false'
    );

    $log->info("deployGamerserver: $game");

    $user  = $settings->{$game}{'node_usr'};
    $suser = $settings->{$game}{'store_usr'};

    $cp_to = $user . "@" . $ip . ":";
    $cp_to .= $settings->{$game}{'node_path'} . "/";

    $cp_from = $settings->{$game}{'store_path'} . "/" . $game;

    my $rsync_cmd  = "rsync -auv --delete -e 'ssh -o StrictHostKeyChecking=no ";
       $rsync_cmd .= "-o PasswordAuthentication=no -o BatchMode=yes' $cp_from $cp_to";
    $log->debug(" $rsync_cmd ");

    unless ( connectSSH( user => $suser, ip => $sip ) ) {
        my $output = $SSH_connections{ $suser . $sip }->capture("$rsync_cmd");
        return $output;
    }
    else {
        return 1;
    }
}

#infoNode( node => 'node5' );
sub infoNode {
    my %args = (
        node => '',
        user => 'minecraft',
        @_,    # argument pair list goes here
    );

    my $output = {};
    my %output = %$output;

    my $node = $args{'node'};
    my $user = $args{'user'};
    my ( $islobby, $isrestricted, $cmd );

    my $ip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $node,
        hash_ref => 'false'
    );
    my $game_ports = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'node',
        value    => $node,
        hash_ref => 'true'
    );

    my @cpu_cmd = q(mpstat -P ALL 2>&1);
    my @pid_cmd = q+pidstat --human -U $(whoami)+;
    my @mem_cmd = q(free -wh;echo; vmstat -wSMa 2>&1; numastat -m -n);
    my $net_cmd = q~vnstat -hg -i $(vnstat | sed -n 's/^[ \t]*\([^:]*\):$/\1/p' | tr '\n' '+' | sed 's/+$//') 2>&1; ~;
      $net_cmd .= q~vnstat -d -i $(vnstat | sed -n 's/^[ \t]*\([^:]*\):$/\1/p' | tr '\n' '+' | sed 's/+$//') 2>&1;~;
      $net_cmd .= q~echo;ip -s link~;
    my $con_cmd = q%ss -Hturp | awk -F'[ ")(:,]*' '$7 !~ /'"$(dig +short -x %;
      $con_cmd .= q%$(hostname -I | awk '{print $1}') | awk -F. '{print $2}' %;
      $con_cmd .= q+)"'|^[ \t]*$|localhost/ {printf "%s %-5s %-5s %-7s <=> %7s %40s \n"  ,$10,$3,$4,$6,$8,$7}' | sort -n -k4 -n -k3;echo;+;
    my $io_cmd  = 'iostat -h 2>&1';
    my $df_cmd  = 'df -h $(pwd) 2>&1; printf "\n\n"; df -hT --total';
    my $neo_cmd = 'neofetch --stdout 2>&1';
    my $du_cmd  = 'echo $(pwd); du -shc * 2>&1 | sort -h';

    foreach my $game ( sort keys %{$game_ports} ) {
        next if ( $game_ports->{$game}{'enabled'} eq '0' );
        $con_cmd .=
          "printf '%-30s' 'Connections to " . $game_ports->{$game}{'name'};
        $con_cmd .= ": ' ; ss -Htu  state established '( sport = :";
        $con_cmd .= $game_ports->{$game}{'port'} . " )' | wc -l;";
    }

    print "$con_cmd\n";

    my $iperf = "
Field	Meaning of Non-Zero Values
errors	Poorly or incorrectly negotiated mode and speed, or damaged network cable.
dropped	Possibly due to iptables or other filtering rules, more likely due to lack of network buffer memory.
overrun	Number of times the network interface ran out of buffer space.
carrier	Damaged or poorly connected network cable, or switch problems.
collsns	Number of collisions, which should always be zero on a switched LAN. 
         Non-zero indicates problems negotiating appropriate duplex mode. 
         A small number that never grows means it happened when the interface came up but hasn't happened since.
";

    unless ( connectSSH( user => $user, ip => $ip ) ) {
        $output{'1_cpu'} = $SSH_connections{ $user . $ip }->capture(@cpu_cmd);
        $output{'3_mem'} = $SSH_connections{ $user . $ip }->capture(@mem_cmd);
        $output{'5_net'} =
          $SSH_connections{ $user . $ip }->capture($net_cmd) . $iperf;
        $output{'2_inet'}  = $SSH_connections{ $user . $ip }->capture($con_cmd);
        $output{'6_io'}    = $SSH_connections{ $user . $ip }->capture($io_cmd);
        $output{'7_disk'}  = $SSH_connections{ $user . $ip }->capture($df_cmd);
        $output{'0_neo'}   = $SSH_connections{ $user . $ip }->capture($neo_cmd);
        $output{'4_proc'}  = $SSH_connections{ $user . $ip }->capture(@pid_cmd);
        $output{'8_files'} = $SSH_connections{ $user . $ip }->capture($du_cmd);

    }
    else {
        $output{'error'} = "$node is offline!";
    }

    return \%output;
}

app->start;

__DATA__


@@ layouts/default.html.ep
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/js/bootstrap.bundle.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.0/dist/css/bootstrap.css">

</head>

</div>
<body>
  <style>
    body  {
        background-image: url("http://www.splatage.com/wp-content/uploads/2021/06/download-wallpaper-x-minecraft-backgroung-green-full-hd-p-hd-background-1478263362k8n4g.jpg");
        background-size: cover;
        background-repeat: repeat-x;
        background-attachment: fixed;

    }
    .custom {
    width: 78px !important;
    margin-right: 3px;
    }
    .data a, .data span, .data tr, .data td { white-space: pre; }
  </style>
<svg xmlns="http://www.w3.org/2000/svg" style="display: none;">
  <symbol id="check-circle-fill" fill="currentColor" viewBox="0 0 16 16">
    <path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>
  </symbol>
  <symbol id="info-fill" fill="currentColor" viewBox="0 0 16 16">
    <path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zm.93-9.412-1 4.705c-.07.34.029.533.304.533.194 0 .487-.07.686-.246l-.088.416c-.287.346-.92.598-1.465.598-.703 0-1.002-.422-.808-1.319l.738-3.468c.064-.293.006-.399-.287-.47l-.451-.081.082-.381 2.29-.287zM8 5.5a1 1 0 1 1 0-2 1 1 0 0 1 0 2z"/>
  </symbol>
  <symbol id="exclamation-triangle-fill" fill="currentColor" viewBox="0 0 16 16">
    <path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/>
  </symbol>
</svg>
 
<nav class="navbar navbar-expand-lg sticky-top navbar-dark bg-dark">
  <div class="container-fluid">
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarTogglerDemo01" 
        aria-controls="navbarTogglerDemo01" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
       <div class="collapse navbar-collapse" id="navbarTogglerDemo01">
    <a class="navbar-brand" href="/">
      <img src="http://www.splatage.com/wp-content/uploads/2021/06/logo.png" alt="" height="50">
    </a>
    

   <div class="container" id="navbarNav">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
      
      % if ( $c->yancy->auth->current_user ) {
        <li class="nav-item">
          <a class="nav-link active" aria-current="page" href="/">home</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="/yancy">settings</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="/minion">minions</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="https://stats.splatage.com">stats</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="https://www.splatage.com">www</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="https://discord.com/channels/697634318067040327/697634318608236556">discord</a>
        </li>

        <li class="nav-item">
        %= link_to Logout => '/yancy/auth/password/logout'
    
        
        </li>
            % }

    % my $flash_message = $c->flash('message');
    % if ($flash_message) {
    <li class="nav-item">
      <div class="alert alert-primary d-flex align-items-center alert-dismissible fade show" role="alert">
        <svg class="bi flex-shrink-0 me-2" width="24" height="24" role="img" aria-label="Info:"><use xlink:href="#info-fill"/></svg>
        <div>
          <%= $flash_message %>
          <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
      </div>  
    % }
    % my $flash_error = $c->flash('error');
    % if ($flash_error) {
      <div class="alert alert-danger d-flex align-items-center alert-dismissible fade show" role="alert">
        <svg class="bi flex-shrink-0 me-2" width="24" height="24" role="img" aria-label="Info:"><use xlink:href="#info-fill"/></svg>
        <div>
          <%= $flash_error %>
          <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
      </div>  
              </li>
      
    % }
    </ul>
    </div>
  </div>
</nav>


  <div height: 100%;>
    <main class="container bg-secondary shadow-lg p-3 mb-5 mt-4 bg-body rounded" style="--bs-bg-opacity: .95;">
        %= content
    </main>
  </div>
</body>
</html>




@@ node.html.ep
% layout 'default';
<!DOCTYPE html>
<html>
  <body>
    <body class="m-0 border-0">
      <div class="container-fluid text-left">
        <div class="alert alert-success" role="alert">
          <h4 class="alert-heading">manage games</h4>
        </div>
      
        % my %nodes   = %$nodes;
        % my %history = %$history;
        % my %expected = %$expected;
      
        % for my $node (sort keys %$nodes) {
          % if ( ! $nodes{$node}{'offline'} ) {


            <div class="media mt-2">
              <a href="/info/<%= $node %>" class="list-group-item-action list-group-item-light">
                <img class="align-self-top mr-1 mt-2 mb-2" 
                  src="http://www.splatage.com/wp-content/uploads/2022/08/application-server-.png"
                  alt="Generic placeholder image" height="80">
                </img> 
                <h3>
                    <%= $node %>
                </h3>
              </a>
            </div>


        <div class="row height: 40px">
        <hr>
        <h5 class="text-success">online</h5>

        </div>
            % for my $game (sort keys %{$nodes{$node}}) {        
            <div class="row height: 40px">
           
                % my $online       = 'true'; # = $node{$game}{'online'};
                % my $isLobby     = 'false'; # = $node{$game}{'isLobby'};
                % my $isRestricted = 'false'; # = $node{$game}{'isRestricted'};
                   
                <div class="col d-flex justify-content-start mb-2 shadow">
                    
                      <div class="media" >
                      <a href="/files/<%= $game %>" class="list-group-item-action list-group-item-light">
                        <img class="zoom align-self-top mr-3" 
                          src="http://www.splatage.com/wp-content/uploads/2022/08/mc_folders.png"
                          alt="Generic placeholder image" height="35">
                        </image>
                      </a>
                      <a href="/log/<%= $node %>/<%= $game %>" class="list-group-item-action list-group-item-light">
                        <img class="zoom align-self-top mr-3" 
                          src=" http://www.splatage.com/wp-content/uploads/2022/08/matrix_log.png"
                          alt="Generic placeholder image" height="35">
                        </image>
                      </a>
                        <img class="align-self-top mr-3" 
                          src="http://www.splatage.com/wp-content/uploads/2021/06/creeper-server-icon.png"
                          alt="Generic placeholder image" height="25">
                          </h4> <%= $game %> </h4>
                        </image>
                      </div>
                </div>
            
                % if (app->minion->lock($game, 0)) {
                <div class="col d-flex justify-content-end mb-2 shadow">
                    <a class="ml-1 btn btn-sm btn-outline-secondary  custom
                        justify-end" data-toggle="tooltip" data-placement="top" title="snapshot game to storage"
                        href="/store/<%= $game %>/<%= $node %>"     role="button">store</a>
                    <a class="ml-1 btn btn-sm btn-outline-info custom     
                        justify-end" data-toggle="tooltip" data-placement="top" title="connect into the network" 
                        href="/link/<%= $game %>/<%= $node %>"      role="button">link</a>
                    <a class="ml-1 btn btn-sm btn-outline-info custom
                                justify-end" data-toggle="tooltip" data-placement="top" title="remove connection from the network"
                                href="/drop/<%= $game %>/<%= $node %>"      role="button">drop</a>
                    <a class="ml-1 btn btn-sm btn-danger     custom
                        justify-end" data-toggle="tooltip" data-placement="top" title="shutdown and copy to storage"
                        href="/halt/<%= $game %>/<%= $node %>"      role="button">halt</a>
                </div>
                % } else {                    
                    <div class="col d-flex justify-content-end mb-2 shadow">
                        <a class="ml-1 btn btn-sm btn-outline-danger  
                        justify-end" href="/minion/locks"      role="button">locked while task is running</a>
                    </div>
                % }        
            </div>   
            % }


        <div class="row height: 40px">
        <hr>
        <h5 class="text-danger">offline</h5>

        </div>
            % for my $game (sort keys %{$expected}) {     
                % if ( $expected{$game}{'node'} eq $node && ! ${nodes}{$node}{$game}{'pid'} ) {
             
                <div class="row height: 40px">
                   <div class="col d-flex justify-content-start mb-2 shadow ">
                    <div class="media" >
                      <a href="/files/<%= $game %>" class="list-group-item-action list-group-item-light">
                        <img class="zoom align-self-top mr-3" 
                          src="http://www.splatage.com/wp-content/uploads/2022/08/mc_folders.png"
                          alt="Generic placeholder image" height="35">
                        </image>
                      </a>
                      <a href="/log/<%= $node %>/<%= $game %>" class="list-group-item-action list-group-item-light">
                        <img class="zoom align-self-top mr-3" 
                          src=" http://www.splatage.com/wp-content/uploads/2022/08/matrix_log.png"
                          alt="Generic placeholder image" height="35">
                        </image>
                      </a>
                      <img class="align-self-top mr-3" 
                        src="http://www.splatage.com/wp-content/uploads/2022/08/minecraft-chest-icon-19.png"
                        alt="Generic placeholder image" height="30">
                        </h4> <%= $game %> </h4>
                      </image>
                    </div>
                  </div>


                    % if (app->minion->lock($game, 0)) {
                        <div class="col d-flex justify-content-end mb-2 shadow">
                        <!--
                            <a class="ml-1 btn btn-sm btn-outline-dark    custom   
                                justify-end" data-toggle="tooltip" data-placement="top" title="migrate to another node"
                                href="/move/<%= $game %>/<%= $node %>"    role="button">move</a>
                            <a class="ml-1 btn btn-sm btn-outline-dark     custom  
                                justify-end" data-toggle="tooltip" data-placement="top" title="update server and plugins"
                                href="/update/<%= $game %>/<%= $node %>"    role="button">update</a>
                           -->     
                            <a class="ml-1 btn btn-sm btn-outline-secondary  custom
                                justify-end" data-toggle="tooltip" data-placement="top" title="copy game data from storage to node"
                                href="/deploy/<%= $game %>/<%= $node %>"    role="button">deploy</a>
                            <a class="ml-1 btn btn-sm btn-outline-info     custom  
                                justify-end" data-toggle="tooltip" data-placement="top" title="remove connection from the network"
                                href="/drop/<%= $game %>/<%= $node %>"      role="button">drop</a>
                            <a class="ml-1 btn btn-sm btn-success    custom
                                justify-end" data-toggle="tooltip" data-placement="top" title="copy from storage and start"
                                href="/boot/<%= $game %>/<%= $node %>"      role="button">boot</a>
                        </div>
                    % } else {
                    <div class="col d-flex justify-content-end mb-2 shadow">
                        <a class="ml-1 btn btn-sm btn-outline-danger 
                        justify-end" data-toggle="tooltip" data-placement="top" title="for safety on a single job can run on each game"
                        href="/minion/locks"      role="button">locked while task is running</a>
                     </div>
                    % }
                 
                </div>  
                % }
            %}
        % }
    % }
  
  </div>  
</body>
</html>


<script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>

<script type="text/javascript">
  $(document).ready(function () {
    %# Scroll down to the bottom
   <!--  $('html, body').animate({scrollTop: $(document).height()},'slow'); -->

    %# Schedule the first update in five seconds
    setTimeout("updatePage()",10000);
  });

  %# This function will update the page
  function updatePage () {
    $('#command-content').load(location.reload(true) + ' #command-content>div');
    $('html, body').animate({scrollTop: $(document).height()});

    %# Schedule the next update in five seconds
    setTimeout("updatePage()",10000);
  }

</script>
<script>
    document.addEventListener("DOMContentLoaded", function (event) {
        var scrollpos = sessionStorage.getItem('scrollpos');
        if (scrollpos) {
            window.scrollTo(0, scrollpos);
            sessionStorage.removeItem('scrollpos');
        }
    });

    window.addEventListener("beforeunload", function (e) {
        sessionStorage.setItem('scrollpos', window.scrollY);
    });
</script>
<style>
.zoom {
  padding: 1px;
  transition: transform .2s; /* Animation */
  width: 30px;
  height: 30px;
  margin: 0 auto;
}

.zoom:hover {
  transform: scale(2.5); /* (150% zoom - Note: if the zoom is too large, it will go outside of the viewport) */
}
</style>

%= javascript begin
    // Automatically submit the form when an input changes
    $( 'form input' ).change( function ( e ) {
        $(this).parents("form").submit();
    } );
% end




@@ index.html.ep
% layout 'default';
<!DOCTYPE html>
<html>

  <div class="alert alert-success" role="alert">
    <h4 class="alert-heading">online nodes and games</h4>
  </div>

<body class="m-0 border-0">
  <div class="container-fluid text-left">
    <div class="row justify-content-start">
      
      
      % my %nodes    = %$nodes;
      % my %expected = %$expected;
      % for my $node (sort keys %$nodes) {
      % if ( ! $nodes{$node}{'offline'} ) {

        <div class="col-12 col-md-3 shadow bg-medium mt-4 rounded">  
     
          <div class="media mt-2">

            <img class="align-self-top mr-1 mt-2 mb-2" 
              src="http://www.splatage.com/wp-content/uploads/2022/08/application-server-.png"
              alt="Generic placeholder image" height="80">
                <a href="/node/<%= $node %>" class="position-absolute bottom-10 end-10 translate-middle badge bg-dark fs-6">
                
                  <%= $node %>

                </a>
             </img>  

                <div class="bg-success text-dark bg-opacity-10 list-group list-group-flush">
                  % for my $game (sort keys %{$nodes{$node}}) {
                    % if ( $game ne 'offline' ) {
                                
                      <a href="/log/<%= $node %>/<%= $game %>" class="fs-5 list-group-item-action list-group-item-success mb-1">
                           <span class="badge badge-primary text-dark">
                       <%= $game %></span>
                        <span style="float:right; mr-1" class="mr-1 fs-6">
                        <small>
                           <%= int($nodes->{$node}->{$game}->{'pcpu'} + 0.5) %>% |
                           <%= int($nodes->{$node}->{$game}->{'rss'}/1024 + 0.5) %>M
                        </small>
                        </span>
                      </a>
                    % }
                  % }
                </div>
                
           
           <div class="bg-success text-dark bg-opacity-10 list-group list-group-flush">     
                %for my $game (sort keys %{$expected}) {
                    % if ( ! $nodes{$node}{$game}{'pid'} && $expected{$game}{'node'} eq $node ) { 
                    
                     <a href="#" class="fs-5 list-group-item-action list-group-item-danger mb-1">
                           <span class="badge badge-primary text-dark">
                       <%= $game %></span>
                        <span style="float:right; mr-1" class="mr-1">
                        <img src="http://www.splatage.com/wp-content/uploads/2022/08/redX.png" alt="X" image" height="25" >
                        </span>
                   
                      </a>
            % }
        % }
            </div>
           </div>
         </div>       
         % }
        % }
        <hr>
        
   <div class="alert alert-danger" role="alert">
    <h4 class="alert-heading">offline nodes</h4>
  </div>
  <div class="container-fluid text-left">
    <div class="row justify-content-start">
      
      
      % my %nodes    = %$nodes;
      % my %expected = %$expected;
      % for my $node (sort keys %$nodes) {
      % if ( $nodes{$node}{'offline'} ) {
        <div class="col-12 col-md-3 shadow bg-medium mt-4 rounded">  
     
          <div class="media mt-2">
            <img class="align-self-top mr-1 mt-2 mb-2" 
              src="http://www.splatage.com/wp-content/uploads/2022/08/application-server-.png"
              alt="Generic placeholder image" height="80">
                <a href="/node/<%= $node %>" class="position-absolute bottom-10 end-10 translate-middle badge bg-dark fs-6">
                
                  <%= $node %>
                </a>
             </img>  
                <div class="bg-success text-dark bg-opacity-10 list-group list-group-flush">
                  % for my $game (sort keys %{$nodes{$node}}) {
                    % if ( $game ne 'offline' ) {
                                
                      <a href="/log/<%= $node %>/<%= $game %>" class="fs-5 list-group-item-action list-group-item-success mb-1">
                           <span class="badge badge-primary text-dark">
                       <%= $game %></span>
                        <span style="float:right; mr-1" class="mr-1 fs-6">
                        <small>
                           <%= int($nodes->{$node}->{$game}->{'pcpu'} + 0.5) %>% |
                           <%= int($nodes->{$node}->{$game}->{'rss'}/1024 + 0.5) %>M
                        </small>
                        </span>
                      </a>
                    % }
                  % }
                </div>
                
           
           <div class="bg-success text-dark bg-opacity-10 list-group list-group-flush">     
                %for my $game (sort keys %{$expected}) {
                   % if ( ! $nodes{$node}{$game}{'pid'} && $expected{$game}{'node'} eq $node ) { 
                    
                     <a href="#" class="fs-5 list-group-item-action list-group-item-danger mb-1">
                           <span class="badge badge-primary text-dark">
                       <%= $game %></span>
                        <span style="float:right; mr-1" class="mr-1">
                        <img src="http://www.splatage.com/wp-content/uploads/2022/08/redX.png" alt="X" image" height="25" >
                        </span>
                   
                     </a>
                   % }
                % }
            </div>
           </div>
         </div>       
         % }
        % }
        <hr>
        
  </div>
</body>
</html>




@@ log.html.ep

<!DOCTYPE html>
<html>
  <head>
    %# This tells phone browsers not to scale out
   %# when first loaded

    <meta name="viewport" content="initial-scale=1.0"/>
    <title>splatage.com term</title>

  </head>
   <meta name="viewport" content="initial-scale=1.0"/>
<body class="m-0 border-0">
  <style type="text/css">

  body {
  word-wrap: break-word;
  color: #00ff00;
  background-image: radial-gradient(
    rgba(0, 150, 0, 0.75), black 120%
  );

  margin: 0;

  padding: 2rem;
  color: lime;
  font: 1rem Inconsolata, monospace;
  text-shadow: 0 0 5px #C8C8C8;
  &::after {
    content: "";

    top: 0;
    left: 0;

    background: repeating-linear-gradient(
      0deg,
      rgba(black, 0.15),
      rgba(black, 0.15) 1px,
      transparent 1px,
      transparent 2px
    );
    pointer-events: none;
  }
}
::selection {
  background: #0080FF;
  text-shadow: none;
}
pre {
  margin: 0;
}

#header {
  display: flex;
  align-items: baseline;
  margin: 0;
  font: 1rem Inconsolata, monospace;
  text-shadow: 0 0 5px #C8C8C8; 
}


 /* blinking cursor */
#cursor {
  background: lime;
  line-height: 15px;
  margin-left: 3px;
  -webkit-animation: blink 0.8s infinite;
  width: 7px;
  height: 15px;
}

@-webkit-keyframes blink {
  0% {background: #222}
  50% {background: lime}
  100% {background: #222}
}
</style>

<%== $log_data %>

<div id="header"><p>minecraft@<%= $node %>:~$ tail -f <%= $game %>.log &</p></div>
<div id="header"><p>minecraft@<%= $node %>:~$ </p><div id="cursor">  </div>

</div>

</body>
</html>

<script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>

<script type="text/javascript">
  $(document).ready(function () {
    %# Scroll down to the bottom
    $('html, body').animate({scrollTop: $(document).height()},'slow');

    %# Schedule the first update in five seconds
    setTimeout("updatePage()",300000);
  });

  %# This function will update the page
  function updatePage () {
    $('#command-content').load(location.reload(true) + ' #command-content>div');
    $('html, body').animate({scrollTop: $(document).height()});

    %# Schedule the next update in five seconds
    setTimeout("updatePage()",300000);
  }

</script>
<script>
    document.addEventListener("DOMContentLoaded", function (event) {
        var scrollpos = sessionStorage.getItem('scrollpos');
        if (scrollpos) {
            window.scrollTo(0, scrollpos);
            sessionStorage.removeItem('scrollpos');
        }
    });

    window.addEventListener("beforeunload", function (e) {
        sessionStorage.setItem('scrollpos', window.scrollY);
    });
</script>




@@ files.html.ep
% layout 'default';
<!DOCTYPE html>

<html>
  <body>
    <body class="m-0 border-0">
      <div class="container-fluid text-left">
        <div class="alert alert-success" role="alert">
          <h4 class="alert-heading">game</h4>
        </div>
      % my @files = @$files; 

<h2> Files </h2>
<%= @files %> and directories

% foreach my $line (@files) { 
<div> <%= $line %> </div> 
%    } 
<hr>


    </div>  
</body>
</html>




@@ node_details.html.ep
% layout 'default';
<!DOCTYPE html>
<html>
    <body class="m-0 border-0">
      <div class="container-fluid text-left">
        <div class="alert alert-success" role="alert">
          <h4 class="alert-heading"> debug info for <%= $node %></h4>
        </div>
%   my %results = %$results;
%  foreach my $title (sort keys %results) { 
        <h3> <%= $title %> </h3> <hr>
    
%      my $info    =  $results{$title};
%#         $info    =~ s/ /\&nbsp;/g;
%      my @lines   = split(/\n/, $info);
    <pre>
%    foreach my $out ( @lines ) {
       <%= $out %>
    % }
    </pre>
% }
</div>
</body>
</html>



@@ login.html.ep
% layout 'default';
<!DOCTYPE html>
<html>
    <body class="m-0 border-0">
      <div class="container-fluid text-left">
        <div class="alert alert-success" role="alert">
          <h4 class="alert-heading"> login...</h4>
        </div>

%= $c->yancy->auth->login_form


</div>
</body>
</html>
