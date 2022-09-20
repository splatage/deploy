
use v5.28;
use Mojolicious::Lite -signatures;
use Net::OpenSSH::Parallel;
use Net::OpenSSH;
use Mojo::mysql;
use DBD::mysql;
use DBI;
use Mojolicious::Plugin::Authentication;
use Mojo::UserAgent;
use IO::Socket::SSL;
use Minion;
use Carp         qw( croak );
use Data::Dumper qw( Dumper );
use POSIX        qw( strftime );
use Time::Piece;
use Time::Seconds;

use strict;
use warnings;


###########################################################
##         Declare Variables for Global Scope            ##
###########################################################

my %ssh_master;
my %notify;

###########################################################
##   Database Connection and Logging                     ##
###########################################################

my $config = plugin Config => { default => {
    db_host             => '127.0.0.1',         # DataBase IP
    db_user             => 'minecraft',         # Database Username
    db_pass             => 'minecraft',         # Database Password
    db_name             => 'deploy',            # Database name
    allow_registration  => '0',                 # NOT recomended. Set to true to create first user
    log_level           => 'info',              # INFO, DEBUG, WARN, TRACE
    default_user        => 'minecraft',         # Default SSH user to perform admin tasks
    ssh_master          => 'true',              # SSH master socket, is faster but prevents treading
    minion_ssh_master   => 'false',             # Same issue, doesn't play nice with threading
    MOJO_REVERSE_PROXY  => 'true',              # Are we behind a reverse proxy - recomended layout
    secret              => 'supersecretsession',# Leave blank to regenerate a rendom secret each restart
    poll_interval       => '2',                 # period in seconds to check logs over ssh

    hypnotoad           => {
#       listen          => ['https://*:3000?cert=keys/domain.crt&key=keys/domain.key'],
        listen          => ['http://*:3000'],
        workers         => 2,
        proxy           => 1,
        trusted_proxies => ['127.0.0.1', '192.168.0.0/16'],
        spare           => 2,
    } },
    file => 'deploy.conf'
};


my $db_string = "mysql://"
    . $config->{'db_user'}
    . ":" . $config->{'db_pass'}
    . "@" . $config->{'db_host'}
    . "/" . $config->{'db_name'};

my $db = Mojo::mysql->strict_mode($db_string);

plugin Minion => { mysql => "$db_string" };

app->log->path(app->home->rel_file(app->moniker . '.log'));

my $log_level;
app->log->level($config->{'log_level'});

if ( $config->{"secret"}) {
    app->secrets([$config->{'secret'}]);
}
else {
    app->secrets([rand]);
}


plugin 'RemoteAddr';

app->log->info("Hello! Starting...");


###########################################################
##               Configure Yancy
###########################################################

plugin Yancy => {
    backend => { mysql => $db },

    # Read the schema configuration from the database
    read_schema => 1,
    schema      => {
    games       => {
            # Show these columns in the Yancy editor
            'x-list-columns' =>
            [qw( name node release port mem_max store enabled isBungee )],
        },
        nodes => {
            'x-list-clomuns' => [qw( name ip enabled isGateway )],
        },
        gs_plugin_settings      => { 'x-hidden' => 'true' },
        global_settings         => { 'x-hidden' => 'true' },
        minion_jobs_depends     => { 'x-ignore' => 'true' },
        minion_workers_inbox    => { 'x-ignore' => 'true' },
        mojo_pubsub_subscribe   => { 'x-ignore' => 'true' },
        isOnline                => { 'x-ignore' => 'true' },
        users                   => {
            'x-id-field'        => 'username',
            required            => [ 'username', 'email', 'password' ],
            properties          => {
                username        => {
                    type        => 'string',
                },
                email           => {
                    type        => 'string',
                    format      => 'email',
                },
                password        => {
                    type        => 'string',
                    format      => 'password',
                },
                is_admin        => {
                    type        => 'boolean',
                    default     => 0,
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

my $cron;
my $settings = readFromDB(
        table    => 'games',
        column   => 'name',
        hash_ref => 'true'
    );

foreach my $game (keys %{$settings}) {
    $cron = $settings->{$game}{'crontab'} or $cron = int(rand(5)) . ' * * * *'; #int(rand(5) + 10)
    app->log->info("scheduling backup for $game $cron");

    plugin Cron => ( $game => {crontab => $cron, code => sub {
        app->minion->enqueue( store => [$game], { attempts => 2, expire => 120 } );
     } } );
}


###########################################################
##    Authentication
###########################################################

app->sessions->default_expiration( 1 * 60 * 60 );

app->yancy->plugin(
    'Auth::Password' => {
        schema          => 'users',
        allow_register  => $config->{'allow_registration'},
        username_field  => 'username',
        email_filed     => 'email',
        password_field  => 'password',
        password_digest => {
            type => 'SHA-512'
        }
    }
);

app->yancy->plugin( Roles => {
    schema => 'users',
    userid_field => 'username',
    role_field   => 'role'
    }
);

group {
    my $route = under '/minion' => sub ($c) {
        my $name = $c->yancy->auth->current_user || '';
        if ( $name ne '' ) {
            return 1;
        }
        $c->res->headers->www_authenticate('Basic');;
        $c->flash( error => "you need to login to do that" );
        $c->redirect_to("/login");
    };
    plugin 'Minion::Admin' => { route => $route };
};

group {
    my $route = under '/status' => sub ($c) {
        my $name = $c->yancy->auth->current_user || '';
        if ( $name ne '' ) {
            return 1;
        }
        $c->res->headers->www_authenticate('Basic');
        $c->flash( error => "you need to login to do that" );
        $c->redirect_to("/login");

    };
    plugin 'Status' => {return_to => '/', route => $route};
};


under sub ($c) {
    # Authenticated
    my $name = $c->yancy->auth->current_user || '';
    if ( $name ne '' ) {
         return 1;
    }
    # Security log authentication attempts
    my $ip = $c->remote_addr;

    app->log->warn("authentication attempt from $ip");
    $c->flash( error => "your ip $ip is logged" );
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

    $c->minion->enqueue( $task => [$game], { attempts => 2, expire => 120 } );
    $c->flash( message => "sending minions to $task $game on $node " );
    $c->redirect_to("/node/$node");
};
app->minion->add_task(
    update => sub ( $job, $game ) {
        my $task = 'update';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 300 );

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

    $c->minion->enqueue( $task => [$game], { attempts => 2, expire => 120 } );

    $c->flash( message => "sending minions to $task $game on $node " );

    $c->redirect_to($c->req->headers->referrer);
};
app->minion->add_task(
    boot => sub ( $job, $game ) {
        my $task = 'boot';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 300 );

        my $deploy = deployGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( deploy => "$game $deploy" );

        my $update = update( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( update => "$game $update" );

        my $boot = bootGame( game => $game, server_bin => $update, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( boot => "$game $boot" );

        my $regist = registerGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( register => "$game $regist" );

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

    $c->minion->enqueue( $task => [$game], { attempts => 2, expire => 120 } );
    $c->flash( message => "sending minions to $task $game on $node " );

    $c->redirect_to($c->req->headers->referrer)
};
app->minion->add_task(
    halt => sub ( $job, $game ) {
        my $task = 'halt';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 60 );

        $job->app->log->info("Job: $task $game begins");

        my $store = storeGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( store => "$game $store" );
        my $halt = haltGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( halt => "$game $halt" );

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

    $c->minion->enqueue( $task => [$game], { attempts => 2, expire => 120 } );
    $c->flash( message => "sending minions to $task $game on $node " );

    $c->redirect_to($c->req->headers->referrer)
};
app->minion->add_task(
    deploy => sub ( $job, $game ) {
        my $task = 'deploy';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 300 );

        $job->app->log->info("Job: $task $game begins");

        my $output = deployGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( deploy => "$game $output" );

        $job->app->log->info("$task $game completed");
        $job->finish(
            { message => "$task $game completed" } );
        app->minion->unlock($lock);
    }
);

## Store #################################################

get '/store/:game/:node' => sub ($c) {

    my $task = 'store';
    my $node = $c->stash('node');
    my $game = $c->stash('game');

    $c->minion->enqueue( $task => [$game], { attempts => 2, expire => 120  } );
    $c->flash( message => "sending minions to $task $game on $node " );

    $c->redirect_to($c->req->headers->referrer)
};
app->minion->add_task(
    store => sub ( $job, $game ) {

        my $task = 'store';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 300 );

        $job->app->log->info("Job: $task $game begins");

        my $output = storeGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( store => "$game $output" );

        $job->app->log->info("$task $game completed");
        $job->finish(
            { message => "$task $game completed" } );
        app->minion->unlock($lock);
    }
);

## Link ###################################################

get '/link/:game/:node' => sub ($c) {

    my $task = 'link';
    my $node = $c->stash('node');
    my $game = $c->stash('game');

    $c->minion->enqueue( $task => [$game], { attempts => 2, expire => 120  } );
    $c->flash( message => "sending minions to $task $game on $node " );

    $c->redirect_to($c->req->headers->referrer)
};
app->minion->add_task(
    link => sub ( $job, $game ) {
        my $task = 'link';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 10 );

        $job->app->log->info("Job: $task $game begins");

        my $output = registerGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( register => "$game $output" );

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

    $c->minion->enqueue( $task => [$game], { attempts => 2, expire => 120  } );
    $c->flash( message => "sending minions to $task $game on $node " );

    $c->redirect_to($c->req->headers->referrer)
};
app->minion->add_task(
    drop => sub ( $job, $game ) {
        my $task = 'drop';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 10 );

        $job->app->log->info("Job: $task $game begins");

        my $output = deregisterGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( deregister => "$game $output" );

        $job->app->log->info("$task $game completed");
        $job->finish( { message => "$task $game completed" } );
        app->minion->unlock($lock);
    }
);

###########################################################
##          Routing
###########################################################

get '/' => sub ($c) {

    my $results = checkIsOnline(
        list_by => 'node',
        node    => '',
        game    => '',
        ssh_master => $config->{'ssh_master'},
    );

    my $expected = readFromDB(
        table    => 'games',
        column   => 'name',
        hash_ref => 'true'
    );

    $c->stash(
        nodes    => $results,
        expected => $expected
    );

    $c->render( template => 'index' );
};

get '/info/:node/' => sub ($c) {

    my $node    = $c->stash('node');
    my $results = infoNode( node => $node, ssh_master => $config->{'ssh_master'} );

    $c->stash( results   => $results );
    $c->render( template => 'node_details' );
};

get '/node/:node' => sub ($c) {

    my $node        = $c->stash('node');
    my $results     = checkIsOnline(
        list_by     => 'node',
        node        => $node,
        game        => '',
        ssh_master  => $config->{'ssh_master'}
    );

    if ( $results->{$node}{'offline'} ) {
        $c->flash(error => "$node doesn't exist");
        $c->redirect_to("/");
    };

    my $ip = readFromDB(
        table       => 'nodes',
        column      => 'ip',
        field       => 'name',
        value       => $node,
        hash_ref    => 'false'
    );

    my $expected    = readFromDB(
        table       => 'games',
        column      => 'name',
        field       => 'node',
        value       => $node,
        hash_ref    => 'true'
    );

    my $jobs = app->minion->jobs(
        {
            queues => ['default'],
            states => [ 'active', 'locked' ],
            tasks  => [ 'boot',   'halt' ]
        }
    );

    $c->render(
        template    => 'node',
        nodes       => $results,
        history     => $jobs,
        expected    => $expected
    );
};

get '/files/:game'  => sub ($c) {

    my $game        = $c->stash('game');
    my @results     = getFiles( game => $game );

    $c->stash( files    => @results );
    $c->render( template => 'files' );
};

get '/debug/:node/:game' => sub ($c) {

    my $node = $c->stash('node');
    my $game = $c->stash('node');
    my ( $results, $expected );

    my $is_configured = readFromDB(
        table       => 'games',
        column      => 'name',
        field       => 'name',
        value       => $game,
        hash_ref    => 'false'
    );

    my $jobs = app->minion->jobs(
        {
            queues  => ['default'],
            states  => [ 'active', 'locked' ],
            tasks   => [ 'boot',   'halt' ]
        }
    );

    $c->render(
        template    => 'node',
        nodes       => $results,
        history     => $jobs,
        expected    => $expected
    );
};

get '/move/:node/:game' => sub ($c) {

    my $node = $c->stash('node');
    my $game = $c->stash('node');
    my ( $results, $expected );

    my $is_configured = readFromDB(
        table       => 'games',
        column      => 'name',
        field       => 'name',
        value       => $game,
        hash_ref    => 'false'
    );

    my $jobs = app->minion->jobs(
        {
            queues  => ['default'],
            states  => [ 'active', 'locked' ],
            tasks   => [ 'boot',   'halt' ]
        }
    );

    $c->render(
        template    => 'node',
        nodes       => $results,
        history     => $jobs,
        expected    => $expected
    );
};


get '/reload' => sub ($c) {
    my $ppid = getppid();
    my $ip = $c->remote_addr;
    kill 'USR2' => $ppid;
    sleep(1);
    $c->flash(message => "reload signal sent to $ppid");
    $c->redirect_to($c->req->headers->referrer);
};


get '/logfile' => sub ($c) {
    app->log->debug("retrieving logfile");
    $c->render(
        template => 'logfile'
        );
};


websocket '/logfile-ws' => sub {
    my $line_count;
    my $self = shift;
    my $file = app->log->path;
    my $results;

    my $game;
    my $ip;
    my $user;
    my $loop;

    $self->inactivity_timeout(1800);

    app->log->debug("reading logfile via websocket");

    my $send_data;
    $send_data = sub {
        $results = updatePage(
                    file        => $file,
                    line_count  => $results->{'line_count'},
                    ip          => $ip,
                    user        => $user,
                    game        => $game,
                 );

        if ( $results->{'new_content'} ) {
            my $content;
            foreach ( split( /\n/, ( $results->{'new_content'} ) ) ) {
                ++$line_count;
                $content = '<div>' . $_ . "</div>\n" . $content;
            }
            $self->send( $content );
        }
    };

    $self->on(finish => sub ($ws, $code, $reason) {
        app->log->info("WebSocket closed with status $code.");
        Mojo::IOLoop->remove($loop);
    });

    $send_data->();
    $loop = Mojo::IOLoop->recurring( 1, $send_data );
};


get '/serverlog/:task' => sub ($c) {

    my $task = $c->stash->{'task'};

    if ( $task eq 'clear' ) {
        my $file = app->log->path;
        truncate $file, 0;
        app->log->debug("log file cleared");

        $c->flash(message => "logfile cleared");
        $c->redirect_to($c->req->headers->referrer);
    };

    if ( $task eq 'info' or $task eq 'debug' or $task eq 'trace' ) {
        app->log->level($task);
        app->log->debug("logging level changed to $task");
        $c->flash(message => "logging level changed to $task");
        $c->redirect_to($c->req->headers->referrer);
    };

    $c->flash(message => "$task..yeah nagh");
    $c->redirect_to($c->req->headers->referrer);

};


websocket '/log/:node/<game>-ws' => sub {
    my $line_count=0;
    my $self = shift;
    my $results;

    my $node = $self->stash('node');
    my $game = $self->stash('game');

    my $user = $self->yancy->auth->current_user->{'username'};

    my $loop;

    $self->inactivity_timeout(1800);

    app->log->info("opening websocket for $user to read $game logfile on $node");


    my $send_data;

    $send_data = sub {

        app->log->debug("$$ websocket: polling $game on $node ");

        my $logdata     = readLog(
            node        => $node,
            game        => $game,
            line_count  => $line_count,
            ssh_master  => $config->{'ssh_master'}
        );

        my $content;

        foreach ( split( /\n/, ( $logdata ) ) ) {
            ++$line_count;
            $content = "<div>" . $_ . "</div>\n" . $content;
        };
        $self->send( $content );
   };

    $self->on(json => sub {
         my ($c, $hash) = @_;

         sendCommand(   command     => $hash->{cmd},
                        game        => $game,
                        node        => $node,
                        ssh_master  => $config->{'minion_ssh_master'}
         );

         # $c->send($user."@".$game.": ".$hash->{cmd} );
         app->log->warn("$user sent console command to $game on $node:");
         app->log->warn(" # $hash->{cmd}");
         Time::HiRes::sleep( 0.2 );
         #sleep(1);
         $send_data->();
    });

    $self->on(finish => sub ($ws, $code, $reason) {
        app->log->info("WebSocket closed with status $code.");
        Mojo::IOLoop->remove($loop);
    });


    $send_data->();
    $loop = Mojo::IOLoop->recurring($config->{'poll_interval'}, $send_data);
};


get '/log/:node/:game' => sub ($c) {

    my $game = $c->stash('game');
    my $node = $c->stash('node');
    app->log->debug("reading $game logfile");

    $c->stash(
        node    => $node,
        game    => $game,

    );

    $c->render(
        template => 'gamelog'
    );
};

get '/test' => sub ($c) {
    my $game = $c->stash('game');
    app->log->debug("upload window for $game");

    $c->stash(
        game => $game
    );

#    $c->render(
#        template => 'uploader',
#    );
};

websocket '/uploads' => sub {
    my $c = shift;
     my $game = $c->stash('game');

    app->log->debug("upload websocket for $game open");

    $c->on( json => sub {
        my ($ws,$file_rh) = @_;
        my $file = Mojo::Asset::File->new();
        $file->add_chunk($file_rh->{contents})->move_to($file_rh->{name});
        app->log->debug("hello $file_rh->{name}");
        sleep 3;
        $ws->send({json => {data => $file_rh->{name}}});
    });

    $c->on(finish => sub {
        my ($ws,$code,$reason) = @_;
        app->log->debug("upload webSocket closed with status $code.");
    });

} => 'save';

any '*' => sub ($c) {
    my $url = $c->req->url->to_abs;
    my $ip  = $c->remote_addr;
    my $user = $c->yancy->auth->current_user->{'username'};
    app->log->warn("possible snooping: $user \[$ip\] $url");
    $c->flash( error => "page doesn't exist" );
    $c->redirect_to("/");
};

websocket '/notify' => sub ($c) {



};

###########################################################
##    Functions
###########################################################

sub updatePage_game {
    my %args = (
       line_count   => '',
       iteration    => '',
       logdata      => '',
       user         => '',
       game         => '',
       file         => '',
       new_content  => '',
    @_ );

    #open(FILE, $args{'logdata'} );

    my $iteration = 0;
    my $new_content = '';

    foreach ( split( /\n/, ( $args{'logdata'} ) ) ) {
        ++$iteration;

        #if ( $iteration > $args{'line_count'} ) {
            ++$args{'line_count'};
            $new_content = $new_content . '<div>' . $_ . "</div>\n";
        #}
    }

    $args{'iteration'}   = $iteration;
    $args{'new_content'} = $new_content;

    return \%args;
}


sub updatePage {
    my %args = (
       line_count   => '',
       iteration    => '',
       ip           => '',
       user         => '',
       game         => '',
       file         => '',
       new_content  => '',
    @_ );

    open(FILE, $args{'file'} );

    my $iteration = 0;
    my $new_content = '';

    while (<FILE>) {
        ++$iteration;

        if ( $iteration > $args{'line_count'} ) {
            ++$args{'line_count'};
            $new_content = $new_content . "<div>" . $_ . "</div>\n";
        }
    }

    close (FILE);

    $args{'iteration'}   = $iteration;
    $args{'new_content'} = $new_content;

    return \%args;
}

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

    my $ssh = connectSSH( user => $user, ip => $ip, ssh_master => $args{'ssh_master'} );
    return $ssh->{'error'} if $ssh->{'error'};
    return $ssh->{'debug'} if $ssh->{'debug'};

    $project_url = $project_url . '/downloads/' . $file_name;
    my $cmd = 'wget -c ' . $project_url . ' -O ' . $path;

    print "connect: $user.$ip   $cmd\n";

    $ssh->{'link'}->system("$cmd");

    $cmd = "sha256sum $path";
    my @sha_file =
      split( / /, $ssh->{'link'}->capture("$cmd") );

    if ( $sha_file[0] eq $sha256 ) {
        return "$file_name SHA: $sha256";
    }
    else {
        return 0;
    }
}

sub readLog {
    my %args        = (
        game        => '',
        node        => '',
        line_count  => '',
        @_,    # argument pair list goes here
    );
    my $game = $args{'game'} or return 1;
    my $node = $args{'node'} or return 1;

    app->log->debug("$game log has $args{'line_count'} lines");

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

    my $ssh = connectSSH( user => $user, ip => $ip, ssh_master => $args{'ssh_master'} );

    return $ssh->{'error'} if $ssh->{'error'};
    return $ssh->{'debug'} if $ssh->{'debug'};

    $ssh->{'link'}->system("screen -p 0 -S $game -X hardcopy -h");
    Time::HiRes::sleep( 0.4 );

    $args{'line_count'} = '1' unless $args{'line_count'};

    my  $cmd;
        $cmd  = "[ -f ~/$game/game_files/hardcopy.0 ] && ";
        $cmd .= q(sed -n '/^>$/d;);
        $cmd .= $args{'line_count'};
        $cmd .= q(,$p' < ~/);
        $cmd .= qq($game/game_files/hardcopy.0);


    app->log->debug($cmd);

    my $logfile =  $ssh->{'link'}->capture($cmd);
       $logfile =~ s/(.{79})\n/$1/g; # Vertial term wraps at 80 characters

      return $logfile;
}

sub readFromDB {
    my %args = (
        table    => '',
        column   => '',
        field    => '',
        value    => '',
        hash_ref => 'true',
        @_
    );

    return 0 if not $args{'table'};
    return 0 if not $args{'column'};

    my $pid=$$;
    my %dbh;

    my $table  = $args{'table'};
    my $column = $args{'column'};
    my $field  = $args{'field'};
    my $value  = $args{'value'};

    app->log->debug("sub readFromDB: PID: $pid Connecting to DB table:$table column:$column field:$field value:$value" );

    $dbh{$pid} = DBI->connect( "DBI:mysql:database=$config->{'db_name'};host=$config->{'db_host'}",
       "$config->{'db_user'}", "$config->{'db_pass'}", { 'RaiseError' => 1, AutoCommit => 1 } );

    my ( $ref, $ref_name, $ref_value );
    my $result = {};
    my %result = %$result;

    my $select = '*';
    $select = $column if ( $args{'hash_ref'} eq 'false' );

    my $query = "SELECT $select FROM $table WHERE enabled = '1'";

    if ( $field ne '' && $value ne '' ) {
        $query .= " AND $field = '$value'";
    }

    $query .= ";";
    app->log->debug("$query");

    my $sth = $dbh{$pid}->prepare($query);
    $sth->execute();

    while ( $ref = $sth->fetchrow_hashref() ) {
        my $index_name;
        $index_name = $column unless $index_name = $ref->{$column};

        foreach ( @{ $sth->{NAME} } ) {
            $ref_name                       = $_;
            $ref_value                      = $ref->{$ref_name};
            $result{$index_name}{$ref_name} = $ref_value;
        }
    }

    $sth->finish();
    $dbh{$pid}->disconnect;
    app->log->debug("DB query complete");

    if ( $args{'hash_ref'} eq 'true' ) {
        return \%result;
    }
    else {
        return $ref_value;
    }
}


sub checkIsOnline {

    my %args = (
        game    => '',
        node    => '',
        pid     => '',
        user    => $config->{'default_user'},
        list_by => 'game',
        ssh_master => '',
        @_,    # argument pair list goes here
    );

    my $enabledNodes = readFromDB(
        table    => 'nodes',
        column   => 'name',
        hash_ref => 'true'
    );

    return 0 unless $enabledNodes;

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
        app->log->debug("Using specified node");
    }
    else {
        @nodes_to_check = ( sort keys %{$enabledNodes} );
        app->log->debug("Using nodes from DB");
    }

    app->log->debug("Query: \[@nodes_to_check\]");


    foreach my $this_node (@nodes_to_check) {

        $return_hash{$this_node}{'offline'}{'offline'} = 'offline';
        app->log->debug("Query $this_node for games...");

        my $ip = $enabledNodes->{$this_node}{'ip'};

        my $ssh = connectSSH( user => $user, ip => $ip, ssh_master => $args{'ssh_master'} );
        if ( not $ssh->{'link'} or $ssh->{'error'}) {
            app->log->debug("Query $this_node for games: LINK FAILED $ssh->{'error'}");
            next;
        }

        delete $return_hash{$this_node}{'offline'};

        my @cmd = "ps axo user:20,pid,ppid,pcpu,pmem,vsz,rss,cmd | grep -i ' [s]creen.*server\\|[j]ava.*server'";
        my $screen_list = $ssh->{'link'}->capture("@cmd");

        my @screen_list = split( '\n', $screen_list );

        foreach my $this_game (@screen_list) {
            my @column = split( / +/, $this_game );

            if ( $column[2] eq '1' ) {

                # SCREEN has ppid of 1. Load the PID and game
                $temp_hash{ $column[1] . $this_node }{'node'} = $this_node;
                $temp_hash{ $column[1] . $this_node }{'ip'}   = $ip;
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

        app->log->warn("[!!] $game is running multiple times!")
          if ( $return_hash->{$list_by}{$game} );

        $return_hash{$list_by}{$game}{'node'} = $temp_hash{$result}{'node'};
        $return_hash{$list_by}{$game}{'user'} = $temp_hash{$result}{'user'};
        $return_hash{$list_by}{$game}{'game'} = $temp_hash{$result}{'game'};
        $return_hash{$list_by}{$game}{'pid'}  = $temp_hash{$result}{'pid'};
        $return_hash{$list_by}{$game}{'ppid'} = $temp_hash{$result}{'ppid'};
        $return_hash{$list_by}{$game}{'pcpu'} = $temp_hash{$result}{'pcpu'};
        $return_hash{$list_by}{$game}{'pmem'} = $temp_hash{$result}{'pmem'};
        $return_hash{$list_by}{$game}{'vsz'}  = $temp_hash{$result}{'vsz'};
        $return_hash{$list_by}{$game}{'rss'}  = $temp_hash{$result}{'rss'};
        $return_hash{$list_by}{$game}{'ip'}   = $temp_hash{$result}{'ip'};
    }

#     my $t_shoot = Dumper(%return_hash);
#     app->log->debug($t_shoot);

    ## Load the offline nodes
    foreach my $offline (@dead_nodes) {
        $return_hash{$offline}{'offline'}{'offline'} = 'true';
    }

    if ( $args{'game'} ) {

        if ( $return_hash{ $args{'game'} }{ $args{'game'} }{'node'} ) {
            app->log->debug( "Found " . $args{'game'} . " on "
                . $return_hash{ $args{'game'} }{ $args{'game'} }{'node'} . " "
                . $return_hash{ $args{'game'} }{ $args{'game'} }{'ip'}
            );

            return "$return_hash{ $args{'game'} }{ $args{'game'} }{'node'}";
        }

        else {
            app->log->debug( "$args{'game'} not found on $return_hash{ $args{'game'} }{ $args{'game'} }{'node'}");
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

    app->log->debug("Registering $game on the network with $gateway");

    $cmd = "servermanager delete " . $game . "^M";

    sendCommand( command => $cmd, game => $gateway, node => $node, ssh_master  => $args{'ssh_master'} );
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

    sendCommand( command => $cmd, game => $gateway, node => $node, ssh_master  => $args{'ssh_master'} );
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

    app->log->debug("Registering $game on the network with $gateway");

    $cmd = "servermanager delete " . $game . "^M";

    sendCommand( command => $cmd, game => $gateway, node => $node, ssh_master  => $args{'ssh_master'} );
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

    my $ssh = connectSSH( user => $suser, ip => $sip, ssh_master => $args{'ssh_master'} );
    return 1 if $ssh->{'error'};


    my @files = $ssh->{'link'}->capture("cd $spath; find $game -type f ");
    chomp(@files);

    #    for (@files) {
    #        print "$_\n";
    #    }
    return \@files;
}


sub sendCommand {
    my %args = (
        game        => '',
        command     => '',
        node        => '',
        ip          => '',
        ssh_master  => '',
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
    $node = checkIsOnline( list_by => 'node', node => '', game => $game, ssh_master => $args{'ssh_master'} ) unless $node;
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

    app->log->debug("Sending command: $command to $game on $ip");

    my $ssh = connectSSH( user => $user, ip => $ip, ssh_master => $args{'ssh_master'} );   #or die "Error establishing SSH" ;

    $ssh->{'link'}->system(
        "screen -p 0 -S $game -X eval 'stuff \"" . $command . "\"^M'" );
    app->log->debug( "\[$ip\] $game: screen -p 0 -S $game -X eval 'stuff \""
          . $command
          . "\"^M'" );
    return;

}


sub connectSSH {
    my %args = (
        user        => '',
        ip          => '',
        ssh_master  => '',
        @_,    # argument pair list goes here
    );

    my $PID = $$;

    unless ( defined $args{'user'} and defined $args{'ip'} ) {
        app->log->warn("Failed to establish SSH: missing username or ip  $args{'user'} $args{'ip'}");
        $args{'error'} = "Failed to establish SSH: missing username or ip  $args{'user'} $args{'ip'}";
        delete $args{'link'};
        return \%args;
    }

    $args{'connection'} = $args{'user'} . "@" . $args{'ip'};

    ## Check for fork and clear previous context
    if ( $ssh_master{ $PID.$args{'user'}.$args{'ip'} } ) {
        $args{'link'} = $ssh_master{ $PID.$args{'user'}.$args{'ip'} };
    }
    else {
        delete $args{'link'};
    }

    if ( $args{'ssh_master'} eq 'true' && defined( $args{'link'} ) ) {
        app->log->debug("Master socket exists $PID.$args{'user'}.$args{'ip'}");

        if ( $args{'link'}->check_master ) {
            app->log->debug("Master socket is HEALTHY $PID.$args{'user'}.$args{'ip'}");
            return \%args;
        }
        else {
            app->log->debug("Master socket is NOT HEALTHY $PID.$args{'user'}.$args{'ip'}");
            $args{'link'}->disconnect();
            delete $args{'link'};
        }
    }

    if ( $args{'ssh_master'} eq 'true' && not defined( $args{'link'} ) ) {
        app->log->info("Creating NEW SSH master socket $PID.$args{'user'}.$args{'ip'}");

        my $socket      = '.ssh_master.' . $args{'connection'} . "_" . $PID;
        $args{'link'}   = Net::OpenSSH->new( $args{'connection'},
            batch_mode  => 1,
            timeout     => 60,
            async       => 0,
            ctl_path    => $socket,
            master_opts => [ '-o StrictHostKeyChecking=no', '-o ConnectTimeout=1' ]
        );

        $ssh_master{ $PID.$args{'user'}.$args{'ip'} } = $args{'link'};
    }

    if ( $args{'ssh_master'} ne 'true' ) {
        app->log->debug("Creating TEMP SSH socket");
        # Use temp ssh - more stable but slower
        my $socket      = '.ssh_master.' . $args{'connection'} . "_" . $PID;
        $args{'link'}   = Net::OpenSSH->new( $args{'connection'},
            batch_mode  => 1,
            timeout     => 60,
            async       => 0,
            master_opts => [ '-o StrictHostKeyChecking=no', '-o ConnectTimeout=1' ]
        );
    }

    if ( $args{'link'}->error ) {
        #$args{'error'} = "Failed to establish SSH: " . $args{'connection'} . ": " . $args{'link'}->error;
        app->log->warn("Failed to establish SSH: ". $args{'connection'} . ": " . $args{'link'}->error);
        delete $args{'link'};
    }
    else {
        app->log->debug("SSH established " . $args{'connection'} . ": " . $args{'link'}->error);
    }
    return \%args;
}


sub haltGame {
    my %args = (
        game => '',
        node => '',
        @_,    # argument pair list goes here
    );

    my $game = $args{'game'};
    my $node = $args{'node'};

    app->log->info("Halting: $game");

    sendCommand( command => "stop^Mend", game => $game, node => $node, ssh_master => $args{'ssh_master'} );

    sleep(30);

    unless ( checkIsOnline( list_by => 'game', node => '', game => $game, ssh_master => $args{'ssh_master'} ) ) {
        app->log->info("Halt $game succeeded");
        return "Halt $game succeeded";
    }
    else {
        app->log->info("Failed to halt $game");
        return "Failed to halt $game";
    }
}


sub storeGame {
    my %args = (
        game => '',
        @_,    # argument pair list goes here
    );

    my $game = $args{'game'} or return "Game cannot be empty";

    my ( $user, $suser, $cp_to, $cp_from );

    my $error = "Aborting task as $game is offline or cannot be reached!! ";
    $error .= "It's potentially catastrophic to overwrite ";
    $error .= "the primary store with data we cannot verify. ";
    $error .= "Please ensure the game is running to prove viabitiy ";
    $error .= "before attempting a sync to the primary data store location";

    return $error
      unless ( checkIsOnline( list_by => 'game', node => '', game => $game, ssh_master => $args{'ssh_master'} ) );

    my $settings = readFromDB(
        table    => 'games',
        column   => 'name',
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

    app->log->info("store Gameserver: $game");

    $user  = $settings->{$game}{'node_usr'};
    $suser = $settings->{$game}{'store_usr'};

    if (!$user || !$suser || !$ip || !$sip ) {
        app->log->warn("Essential variable missing user:$user store_user:$suser ip:$ip store_ip:$sip");
        return "Essential variable missing user:$user store_user:$suser ip:$ip store_ip:$sip";
    };

    unless ( $settings->{$game}{'isBungee'} ) {
       sendCommand(
            command     => 'say Backup starting...^Msave-off^Msave-all',
            game        => $game,
            node        => $settings->{$game}{'node'},
            ip          => $ip,
            ssh_master  => $args{'ssh_master'}
        );
        sleep(0.5);
    };

    $cp_from = $user . "@" . $ip . ":";
    $cp_from .= $settings->{$game}{"node_path"} . "/" . $game;

    $cp_to = $settings->{$game}{"store_path"} . "/";

    app->log->debug(" $cp_from $cp_to ");

    my $ssh = connectSSH( user => $suser, ip => $sip, ssh_master => $args{'ssh_master'} );
    return $ssh->{'error'} if $ssh->{'error'};
    return $ssh->{'debug'} if $ssh->{'debug'};

    my $rsync_cmd  = q( rsync -auv --delete );
       $rsync_cmd .= q( --exclude='plugins/*jar' --exclude='hardcopy.*' --exclude='screenlog.*' );
       $rsync_cmd .= q( -e 'ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no );
       $rsync_cmd .= qq( -o BatchMode=yes' $cp_from $cp_to );

    app->log->debug("$rsync_cmd");

    my $output = $ssh->{'link'}->capture("$rsync_cmd");

    unless ( $settings->{$game}{'isBungee'} ) {
        sendCommand(
            command     => "co purge t:30d",
            game        => $game,
            node        => $settings->{$game}{'node'},
            ip          => $ip,
            ssh_master  => $args{'ssh_master'}
        );
        sendCommand(
            command     => "say Backup complete^Msave-on",
            game        => $game,
            node        => $settings->{$game}{'node'},
            ip          => $ip,
            ssh_master  => $args{'ssh_master'}
        );
    };

    return $output;
}


sub bootGame {
    my %args = (
        game       => '',
        server_bin => '',
        upgrade    => '',
        @_,    # argument pair list goes here
    );

    my $game = $args{'game'};

    my $upgrade = "--forceUpgrade" if $args{'upgrade'};

    my ( $user, $suser, $cp_to, $cp_from );

    return "$game is already online"
      if ( checkIsOnline( list_by => 'game', node => '', game => $game, ssh_master => $args{'ssh_master'} ) );

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

    my $path = qq( $settings->{$game}{'node_path'}/$game/game_files );
    my $boot_strap;
       $boot_strap  = qq( mkdir -p $path && cd $path  && );
       $boot_strap .= qq( echo "eula=true" > eula.txt && );
       $boot_strap .= qq( [ -f spigot.yml ] && sed -i '/bungeecord:/s/false/true/' spigot.yml && );
       $boot_strap .= qq( [ -f paper.yml  ] && sed -i '/bungee-online-mode:/s/false/true/' paper.yml && );
       $boot_strap .= qq( [ -f server.properties ] && sed -i '/online-mode=/s/true/false' server.properties  );


    my $invocation;
       $invocation  = qq( cd $path && screen -h 50000 -L -dmS $game );
       $invocation .= qq( $settings->{$game}{'java_bin'} );
       $invocation .= qq( -Xms$settings->{$game}{'mem_min'} );
       $invocation .= qq( -Xmx$settings->{$game}{'mem_max'} );
       $invocation .= qq( $settings->{$game}{'java_flags'} );
       $invocation .= qq( -jar $args{'server_bin'} $upgrade );
       $invocation .= qq( --port $settings{$game}{'port'} );
       $invocation .= qq( nogui server );
       $invocation =~ s/\n+/ /g;s/  / /g;

    app->log->debug("$invocation");
    $user = $settings->{$game}{'node_usr'};

    my $ssh = connectSSH( user => $user, ip => $ip, ssh_master => $args{'ssh_master'} );
    return $ssh->{'error'} if $ssh->{'error'};
    return $ssh->{'debug'} if $ssh->{'debug'};

    $ssh->{'link'}->system("$invocation");

    my @cmd = qq(screen -S $game -X colon "logfile flush 5^M");
    $ssh->{'link'}->system(@cmd);

    $ssh->{'link'}->system(@cmd);


    sleep(10);

    if ( checkIsOnline( list_by => 'game', node => '', game => $game, ssh_master => $args{'ssh_master'} ) ) {
        app->log->info("Started $game");
        return 0;
    }
    else {
        app->log->info("Failed to start $game");
        return 1;
    }
}


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
      if ( checkIsOnline( list_by => 'game', node => '', game => $game, ssh_master => $args{'ssh_master'} ) );

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

    app->log->info("deployGamerserver: $game");

    $user  = $settings->{$game}{'node_usr'};
    $suser = $settings->{$game}{'store_usr'};

    if (!$user || !$suser || !$ip || !$sip ) {
        app->log->warn("Essential variable missing user:$user store_user:$suser ip:$ip store_ip:$sip");
        return "Essential variable missing user:$user store_user:$suser ip:$ip store_ip:$sip";
    }

    $cp_to = $user . "@" . $ip . ":";
    $cp_to .= $settings->{$game}{'node_path'} . "/";

    $cp_from = $settings->{$game}{'store_path'} . "/" . $game;

    my $rsync_cmd  = "rsync -auv --delete -e 'ssh -o StrictHostKeyChecking=no ";
       $rsync_cmd .= "-o PasswordAuthentication=no -o BatchMode=yes' $cp_from $cp_to";
    app->log->debug(" $rsync_cmd ");

    my $ssh = connectSSH( user => $suser, ip => $sip, ssh_master => $args{'ssh_master'} );
    return $ssh->{'error'} if $ssh->{'error'};
    return $ssh->{'debug'} if $ssh->{'debug'};

    my $output = $ssh->{'link'}->capture("$rsync_cmd");
    return $output;
}


sub infoNode {
    my %args = (
        node => '',
        user => $config->{'default_user'},
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
#    my $neo_cmd = 'neofetch --stdout 2>&1';
    my @neo_cmd = q(neofetch|sed 's/\x1B\[[0-9?;]*[a-zCAD0-9]//g');
#    my $du_cmd  = 'echo $(pwd); du -shc * 2>&1 | sort -h';

    foreach my $game ( sort keys %{$game_ports} ) {
        next if ( $game_ports->{$game}{'enabled'} eq '0' );
        $con_cmd .=
          "printf '%-30s' 'Connections to " . $game_ports->{$game}{'name'};
        $con_cmd .= ": ' ; ss -Htu  state established '( sport = :";
        $con_cmd .= $game_ports->{$game}{'port'} . " )' | wc -l;";
    }

    print "$con_cmd\n";

    my $iperf = "
-------------------------------------
Field      Meaning of Non-Zero Values
-------------------------------------

errors     Poorly or incorrectly negotiated mode and speed, or damaged network cable.
dropped    Possibly due to iptables or other filtering rules, more likely due to lack of network buffer memory.
overrun    Number of times the network interface ran out of buffer space.
carrier    Damaged or poorly connected network cable, or switch problems.
collsns    Number of collisions, which should always be zero on a switched LAN.
           Non-zero indicates problems negotiating appropriate duplex mode.
           A small number that never grows means it happened when the interface came up but hasn't happened since.
";
    my $ssh = connectSSH( user => $user, ip => $ip, ssh_master => $args{'ssh_master'} );
    return $ssh->{'error'} if $ssh->{'error'};
    return $ssh->{'debug'} if $ssh->{'debug'};

        $output{'1_cpu'}   = $ssh->{'link'}->capture(@cpu_cmd);
        $output{'3_mem'}   = $ssh->{'link'}->capture(@mem_cmd);
        $output{'5_net'}   = $ssh->{'link'}->capture($net_cmd) . $iperf;
        $output{'2_inet'}  = $ssh->{'link'}->capture($con_cmd);
        $output{'6_io'}    = $ssh->{'link'}->capture($io_cmd);
        $output{'7_disk'}  = $ssh->{'link'}->capture($df_cmd);
        $output{'0_neo'}   = $ssh->{'link'}->capture(@neo_cmd);
        $output{'4_proc'}  = $ssh->{'link'}->capture(@pid_cmd);
#        $output{'8_files'} = $ssh->{'link'}->capture($du_cmd);

    return \%output;
}

app->start;

__DATA__


@@ layouts/template.html.ep
<!DOCTYPE html>
<html>
<head>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/css/bootstrap.min.css"
        rel="stylesheet"
        integrity="sha384-iYQeCzEYFbKjA/T2uDLTpkwGzCiq6soy8tYaI1GyVh/UjpbCx/TYkiZhlZB6+fzT"
        crossorigin="anonymous">

    <meta name="viewport" content="width=device-width, initial-scale=1">

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

#top-alert {
    position: fixed;
    top: 0;
    right: 0;
    z-index: 99999;
    width: 40%;
}

.data a, .data span, .data tr, .data td { white-space: pre; }

#command-content{
    text-indent: -20px;
    padding-left: 25px; font-size: small; color: #41FF00;
    height: 65vh;
    overflow: auto;
    display: flex;
    flex-direction: column-reverse;
    background-color: black;
}

.zoom {
    padding: 1px;
    transition: transform .2s; /* Animation */
    width: 30px;
    height: 30px;
    margin: 0 auto;
}

.zoom:hover {
    transform: scale(1.5);
}
html {

  scroll-behavior: auto !important;

}

</style>
</head>

<body class="d-flex flex-column min-vh-100">

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

    % my $flash_message = $c->flash('message');
    % if ($flash_message) {
    <div id="top-alert" class="alert alert-primary d-flex align-items-center alert-dismissible fade show alert-fadeout" role="alert">
        <svg class="bi flex-shrink-0 me-2" width="24" height="24" role="img" aria-label="Info:"><use xlink:href="#info-fill"/></svg>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        <%= $flash_message %>
    </div>
    % }


    % my $flash_error = $c->flash('error');
    % if ($flash_error) {
    <div id="top-alert" class="alert alert-danger d-flex align-items-center alert-dismissible fade show alert-fadeout" role="alert">
        <svg class="bi flex-shrink-0 me-2" width="24" height="24" role="img" aria-label="Info:"><use xlink:href="#info-fill"/></svg>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        <%= $flash_error %>
    </div>
    % }


<nav class="navbar navbar-expand-lg static-top sticky-top navbar-dark bg-dark">
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
      <ul class="navbar-nav me-auto mb-2 mb-sm-0 nav-tabs">
      % if ( $c->yancy->auth->current_user ) {
        <li class="nav-item">
          <a class="btn-sm btn-outline-secondary nav-link" role="button" aria-current="page" href="/"><h6>home</h6></a>
        </li>
        <li class="nav-item">
          <a class="btn-sm btn-outline-secondary nav-link" role="button" href="/yancy"><h6>settings</h6></a>
        </li>
        <li class="nav-item">
          <a class="btn-sm btn-outline-secondary nav-link" role="button" href="/minion"><h6>minions</h6></a>
        </li>
        <li class="nav-item">
          <a class="btn-sm btn-outline-secondary nav-link" role="button" href="/status"><h6>status</h6></a>
        </li>
        <li class="nav-item">
          <a class="btn-sm btn-outline-secondary nav-link" role="button" href="/logfile"><h6>logfile</h6></a>
        </li>
        <li class="nav-item">
          <a class="btn-sm btn-outline-secondary nav-link" role="button" href="/reload"><h6>reload</h6></a>
        </li>
        <li class="nav-item">
          <a class="btn-sm btn-outline-warning nav-link" role="button" href="/yancy/auth/password/logout"><h6>logout</h6></a>
        </li>
     <li class="nav-item">
          <a class="btn-sm btn-outline-warning nav-link" role="button" target="_blank"
          href="https://github.com/splatage/deploy/wiki"><h6>help</h6></a>
        </li>
     % }
    </ul>
    </div>
  </div>
</nav>

  <div height: 100%;>
    <main class="container-xl bg-secondary shadow-lg mb-1 mt-1 p-3 bg-body rounded" style="--bs-bg-opacity: .90;">
        %= content
          <div class="d-flex align-items-center">
            <strong class="spinner-hide">Loading...</strong>
          <div class="spinner-hide spinner-border ms-auto" role="status" aria-hidden="true"></div>
        </div>
    </main>
  </div>


<footer class="bg-dark text-center text-white mt-auto">
  <!-- Grid container -->
  <!-- Copyright -->
  <div class="text-center p-3" style="background-color: rgba(0, 0, 0, 0.2);">
    © 2022 Copyright:
    <a class="text-white" href="https://splatage.com/">splatage.com</a>
  </div>
  <!-- Copyright -->
</footer>

<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js"></script>
<link rel="stylesheet" href="https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/themes/smoothness/jquery-ui.css">
<script src="https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/jquery-ui.min.js"></script>

<script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"
    integrity="sha384-oBqDVmMz9ATKxIep9tiCxS/Z9fNfEXiDAYTujMAeBAsjFuCZSmKbSSUnQlmh/jp3"
    crossorigin="anonymous">
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/js/bootstrap.min.js"
    integrity="sha384-7VPbUDkoPSGFnVtYi0QogXtr74QeVeeIs99Qfg5YCF+TidwNdjvaKZX19NZ/e6oz"
    crossorigin="anonymous">
</script>

<!--  dismiss spinner once page has loaded -->
<script type="text/javascript">
    $(document).ready(function() {
        $('.spinner-hide').hide();
    });
</script>

<!--  fade out alerts
<script>
    setTimeout(function() {
        bootstrap.Alert.getOrCreateInstance(document.querySelector(".alert")).close();
    }, 5000)
</script>
-->

<!--  fade out alerts -->
<script>
$(document).ready(function () {

window.setTimeout(function() {
    $(".alert-fadeout").fadeTo(1000, 0).slideUp(1000, function(){
        $(this).remove();
    });
}, 5000);
});
</script>
<!--  remember scroll position
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
-->
</body>
</html>



@@ node.html.ep
% layout 'template';

<meta http-equiv="refresh" content="10">
<html>
  <body>
    <body class="m-0 border-0">
      <div class="container-fluid text-left">

        <div class="alert alert-success alert-dismissible fade show" role="alert">
            <h4 class="alert-heading">manage games</h4>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>

        % my %nodes     = %$nodes;
        % my %history   = %$history;
        % my %expected  = %$expected;

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

                % my $online        = 'true';   # = $node{$game}{'online'};
                % my $isLobby       = 'false';  # = $node{$game}{'isLobby'};
                % my $isRestricted  = 'false';  # = $node{$game}{'isRestricted'};
<!-- NodePage Buttons -->
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
                        <img class="zoom align-self-top mr-3"
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
                        justify-end" href="/minion/locks"      role="button">task is running</a>
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
                      <img class="zoom align-self-top mr-3"
                        src="http://www.splatage.com/wp-content/uploads/2022/08/minecraft-chest-icon-19.png"
                        alt="Generic placeholder image" height="30">
                        </h4> <%= $game %> </h4>
                      </image>
                    </div>
                  </div>


                    % if (app->minion->lock($game, 0)) {
                        <div class="col d-flex justify-content-end mb-2 shadow">
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
                        href="/minion/locks"      role="button">task is running</a>
                     </div>
                    % }
                </div>
                % }
            %}
        % }
    % }
  </div>

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

</body>
</html>


@@ index.html.ep
% layout 'template';

<html>

<div class="alert alert-success alert-dismissible fade show" role="alert">
  <h4 class="alert-heading">online nodes</h4>
  <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
</div>

<body class="m-0 border-0">
  <div class="container-fluid text-left">
    <div class="row justify-content-start">

      % my %nodes    = %$nodes;
      % my %expected = %$expected;
      % for my $node (sort keys %$nodes) {
      % if ( ! $nodes{$node}{'offline'}{'offline'} ) {

        <div class="col-12 col-md-3 shadow bg-medium mt-4 mb-2 rounded">

          <div class="media mt-2 mb-2">

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

                     <a href="/log/<%= $node %>/<%= $game %>" class="fs-5 list-group-item-action list-group-item-danger mb-1">
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

<div class="alert alert-danger alert-dismissible fade show" role="alert">
  <h4 class="alert-heading">offline nodes</h4>
  <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
</div>

  <div class="container-fluid text-left">
    <div class="row justify-content-start">

      % %nodes    = %$nodes;
      % %expected = %$expected;
      % for my $node (sort keys %$nodes) {
      % if ( $nodes{$node}{'offline'}{'offline'} ) {
        <div class="col-12 col-md-3 shadow bg-medium mt-4 rounded">

          <div class="media mt-2">
            <img class="align-self-top mr-1 mt-2 mb-2"
              src="http://www.splatage.com/wp-content/uploads/2022/08/application-server-.png"
              alt="Generic placeholder image" height="80">
                <a href="#" class="position-absolute bottom-10 end-10 translate-middle badge bg-dark fs-6">

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
                         <%= $game %>
                       </span>
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


@@ files.html.ep
% layout 'template';

<!DOCTYPE html>

<html>
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
        % }
        <hr>
      </div>
   </body>
</html>



@@ node_details.html.ep
% layout 'template';

<!DOCTYPE html>
<html>
    <body class="m-0 border-0">
      <div class="container-fluid text-left">
        <div class="alert alert-success" role="alert">
          <h4 class="alert-heading"> debug info for <%= $node %></h4>
        </div>
<div class="accordion accordion-flush" id="accordionFlushExample">
% my %numbers = (1 => 'One', 2 =>'Two', 3 => 'Three', 4 => 'Four', 5 => 'Five', 6 => 'Six', 7 => 'Seven', 8 => 'Eight', 9 => 'Nine');
% my $count;
% my %results = %$results;
% my $show = 'show';
% foreach my $title (sort keys %results) {
%   my $info    =  $results{$title};
%   my @lines   = split(/\n/, $info);
%   $count++;
%   $show = undef unless ($count eq 1);
  <div class="accordion-item">
    <h2 class="accordion-header" id="flush-heading<%= $numbers{$count} %>">
      <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
        data-bs-target="#flush-collapse<%= $numbers{$count} %>" aria-expanded="false"
        aria-controls="flush-collapse<%= $numbers{$count} %>">
        <strong> <%= $title %> </strong> <hr>
      </button>
    </h2>
    <div id="flush-collapse<%= $numbers{$count} %>" class="accordion-collapse collapse <%= $show %>"
        aria-labelledby="flush-heading<%= $numbers{$count} %>"
        data-bs-parent="#accordionFlushExample">
      <div class="accordion-body">
        <pre>
          % foreach my $out ( @lines ) {
          <%= $out %>
          % }
        </pre>
      </div>
    </div>
  </div>

% }


</div>

</div>
</body>
</html>


@@ login.html.ep
% layout 'template';

<html>
    <body class="m-0 border-0 mt-5"
        style="background-size: cover; background-image: url('https://cdn.mos.cms.futurecdn.net/52K7sgnQLSJ8ggfyfvz9yB-970-80.jpg.webp');">
      <div class="container-fluid text-left bg-opacity-10" style="--bs-bg-opacity: .10;">
        %= $c->yancy->auth->login_form
      </div>
    </body>
</html>


@@ logfile.html.ep
% layout 'template';

<html>
    <body class="m-0 border-0">
      <div class="container-fluid text-left">
        <div class="alert alert-success alert-dismissible fade show alert-fadeout" role="alert">
            <h4 class="alert-heading">server logfile</h4>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
      </div>

        <div id='command-content' class="text-wrap container-sm text-break">
            %# This is the command output
        </div>

        <!-- /serverlog/:task   -->
        <div class="d-grid gap-2 d-md-block">
            <a class="btn btn-outline-warning" href="/serverlog/clear" role="button">clear</a>
            <a class="btn btn-outline-success" href="/serverlog/info" role="button">info</a>
            <a class="btn btn-outline-success" href="/serverlog/debug" role="button">debug</a>
            <a class="btn btn-outline-success" href="/serverlog/trace" role="button">trace</a>
        </div>
  </div>
  <script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <script type="text/javascript">
      $(document).ready(function () {
            var ws_host = window.location.href;
            ws_host = ws_host.replace(/http:/,"ws:");
            ws_host = ws_host.replace(/https:/,"wss:");
            ws_host = ws_host + "-ws";
            var socket = new WebSocket(ws_host);

            socket.onmessage = function (msg) {
                $('#command-content').prepend(msg.data);
            }

            function send(e) {
                if (e.keyCode !== 13) {
                    return false;
                }

                var cmd = document.getElementById('cmd').value;
                document.getElementById('cmd').value = '';
                console.log('send', cmd);
                socket.send(JSON.stringify({cmd: cmd}));
            }

      document.getElementById('cmd').addEventListener('keypress', send);
      document.getElementById('cmd').focus();
      });
    </script>
</body>
</html>


@@ gamelog.html.ep
% layout 'template';

<html>
    <body class="m-0 border-0">
      <div class="container-fluid text-left">
        <div class="alert alert-success alert-dismissible fade show alert-fadeout" role="alert">
            <h4 class="alert-heading">command console: <%= $game %> on <%= $node %></h4>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
        <div id='command-content' class="text-wrap container-sm text-break">
            %# This is the command output
        </div>
    </div>
<!--    <div class="input-group mb-2 container bg-secondary shadow-lg bg-body rounded"> -->
    <div class="input-group input-group-sm mb-3">

        <button class="btn btn-primary" type="button" data-bs-toggle="offcanvas" data-bs-target="#offcanvasExample" aria-controls="offcanvasExample">
            Options
        </button>

<!-- Side Panel -->
        <div class="offcanvas offcanvas-start" tabindex="-1" id="offcanvasExample" aria-labelledby="offcanvasExampleLabel">
            <div class="offcanvas-header">
                <h5 class="offcanvas-title" id="offcanvasExampleLabel">Control Options</h5>
                <button type="button" class="btn-close" data-bs-dismiss="offcanvas" aria-label="Close"></button>
            </div>
            <div class="offcanvas-body">

             % if (app->minion->lock($game, 0)) {

                <h6 class="mt-3">storage</h6>
                <hr>
                <div class="list-group">
                    <a href="/store/<%= $game %>/<%= $node %>"
                        class="list-group-item list-group-item-action list-group-item-secondary">store</a>
                    <a href="/deploy/<%= $game %>/<%= $node %>"
                        class="list-group-item list-group-item-action list-group-item-secondary">deploy</a>
                </div>

                <h6 class="mt-3">network</h6>
                <hr>
                <div class="list-group">
                    <a href="/drop/<%= $game %>/<%= $node %>"
                        class="list-group-item list-group-item-action list-group-item-secondary">drop</a>
                    <a href="/deploy/<%= $game %>/<%= $node %>"
                        class="list-group-item list-group-item-action list-group-item-secondary">link</a>
                </div>

                <h6 class="mt-3">power</h6>
                <hr>
                <div class="list-group">
                    <a href="/halt/<%= $game %>/<%= $node %>"
                        class="list-group-item list-group-item-action list-group-item-dark">halt</a>
                    <a href="/boot/<%= $game %>/<%= $node %>"
                        class="list-group-item list-group-item-action list-group-item-dark">boot</a>
                </div>

                % } else {
                    <div class="col d-flex justify-content-end mb-2 shadow">
                        <a class="ml-1 btn btn-sm btn-outline-danger
                        justify-end" href="/minion/locks"      role="button">task is running</a>
                    </div>
                % }
            </div>

        </div>
<!-- Console Form -->
            <span class="input-group-text" id="inputGroup-sizing-sm"><b><%= $game %>@<%= $node %> :~ </small></b></span>
            <input type="text" autocomplete="off" class="form-control" id="cmd" placeholder="console"
              aria-label="Sizing example input" aria-describedby="inputGroup-sizing-sm">
        </div>
</body>

<!-- $('html, body').animate({scrollTop: $(document).height()}, 'slow'); -->
<script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <script type="text/javascript">
      $(document).ready(function () {
            var ws_host = window.location.href;
            ws_host = ws_host.replace(/http:/,"ws:");
            ws_host = ws_host.replace(/https:/,"wss:");
            ws_host = ws_host + "-ws";
            var socket = new WebSocket(ws_host);

            socket.onmessage = function (msg) {
                $('#command-content').prepend(msg.data);
            }

            function send(e) {
                if (e.keyCode !== 13) {
                    return false;
                }

                var cmd = document.getElementById('cmd').value;
                document.getElementById('cmd').value = '';
                console.log('send', cmd);
                socket.send(JSON.stringify({cmd: cmd}));
            }

      document.getElementById('cmd').addEventListener('keypress', send);
      document.getElementById('cmd').focus();
      });
    </script>
</html>


@@ uploader.html.ep
% layout 'template';

%= stylesheet begin

    table#holder {
        border: 5px dashed #CCC;
        width:400px;
        font-family:Verdana;
    }
    table#holder tr:first-child {
        height:50px;
        text-align:center;
    }
    table#holder tr:last-child {
        height:300px;
        line-height: 50px;
    }
    table#holder li img {
        height: 30px;
    }

% end

%= javascript begin

function transViaWS (url,files) {

      console.log("inside the websocket block: ", url);

      var ws     = new WebSocket(url);
      var reader = new FileReader();
      reader.fileName =  files.item(0).name;

      var i = 0;

      reader.onloadend = function(event) {
          var contents = event.target.result;
          var name     = event.target.fileName;
          $('#fileList').text('Tranforming ' + name)
          ws.send(
                JSON.stringify( {'contents':contents, 'name': name} )
          );
          console.log(event.target.fileName);
          i++;
      };

      reader.onprogress = function(data) {
        if (data.lengthComputable){
            var progress = parseInt( ((data.loaded / data.total) * 100), 10 );
            console.log(progress);
        }
      }

      ws.onopen = function () {
          reader.readAsText( files.item(0) );
      };

      ws.onmessage = function (evt) {
          var data = JSON.parse(evt.data);
          console.log(i);
          console.log(data);
          if (i < files.length){
            reader.fileName = files.item(i).name;
            reader.readAsText( files.item(i) );
          }
          else {
            ws.close();
          }
      };
}


% end

%= javascript begin

$(document).ready ( function () {
    $('#holder').on({
        'dragover dragenter': function(e) {
            e.preventDefault();
            e.stopPropagation();
        },
        'drop': function(e) {
            // console.log(e.originalEvent, instanceof, DragEvent);
            var dataTransfer = e.originalEvent.dataTransfer;
            if (dataTransfer && dataTransfer.files.length) {
                e.preventDefault();
                e.stopPropagation();
                files  = dataTransfer.files;
                transViaWS("<%= url_for('save')->to_abs %>", files);
            }
        }
    });
});

% end

<table id="holder">
  <tr>
    <td>Drop files here</td>
  </tr>
  <tr>
    <td><ul id="fileList"></ul></td>
  </tr>
</table>
