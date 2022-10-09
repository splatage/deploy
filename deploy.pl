
use v5.28;

use Mojolicious::Lite -signatures;
use Net::OpenSSH;
use Mojo::mysql;
use DBD::mysql;
use DBI;
use Mojolicious::Plugin::Authentication;
use Mojo::UserAgent;
use Mojo::JSON qw(decode_json encode_json);
use Mojo::File  qw(path );
use Mojo::Util qw(b64_encode b64_decode url_escape url_unescape);
use Digest::Bcrypt;
use Data::Entropy::Algorithms qw(rand_bits);
use Number::Bytes::Human qw(format_bytes parse_bytes);
use Minion;
use Data::Dumper qw( Dumper );
use POSIX        qw( strftime );
use Time::Piece;
use Time::Seconds;
use Text::ParseWords;

use strict;
use warnings;
no warnings qw(experimental::signatures);

plugin 'StaticCache' => { even_in_dev => 1, max_age => 2592000 };

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
    poll_interval       => '10',                 # period in seconds to check logs over ssh

    hypnotoad           => {
#       listen          => ['https://*:3000?cert=keys/domain.crt&key=keys/domain.key'],
        listen          => ['http://*:3000'],
        workers         => 1,
        proxy           => 1,
        trusted_proxies => ['127.0.0.1', '192.168.0.0/16'],
        spare           => 3,
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

( $config->{"secret"} ) ? app->secrets([$config->{'secret'}]) : app->secrets([rand]);

app->max_request_size($config->{'max_upload_size'} * 1024 * 1024);

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
            [qw( name node pool release port mem_max store enabled isBungee )],
            required        => [ 'name', 'pool' ],
        },
    nodes => {
        'x-list-clomuns'    => [qw( name ip enabled isGateway )],
    },
    gs_plugin_settings      => { 'x-hidden' => 'true' },
    global_settings         => { 'x-hidden' => 'true' },
    minion_jobs_depends     => { 'x-ignore' => 'true' },
    minion_workers_inbox    => { 'x-ignore' => 'true' },
    mojo_pubsub_subscribe   => { 'x-ignore' => 'true' },
    isOnline                => { 'x-ignore' => 'true' },
    users                   => {
        'x-id-field'        => 'username',
        required            => [ 'username', 'email' ],
        properties          => {
            username        => {
                'x-order'   => 1,
                type        => 'string',
            },
            email           => {
                'x-order'   => 2,
                type        => 'string',
                format      => 'email',
            },
            password        => {
                'x-order'   => 3,
                type        => 'string',
                format      => 'password',
            },
            super_user      => {
                'x-order'   => 4,
                type        => 'boolean',
                default     => 0,
            },
            enabled         => {
                'x-order'   => 5,
                type        => 'boolean',
                default     => 1,
            },
        },
    },
    perms                   => {
        'x-id-field'        => 'username',
        required            => [ 'username' ],
        properties          => {
            username        => {
                'x-order'   => 1,
                type        => 'string',
            },
            pool            => {
                'x-order'   => 2,
                type        => 'string',
            },
            admin           => {
                'x-order'   => 3,
                type        => 'boolean',
                default     => 0,
            },
            enabled         => {
                'x-order'   => 4,
                type        => 'boolean',
                default     => 1,
            },
        },
    },
    },
    editor => {
        require_user => { super_user => 1 },
    },
};


###########################################################
##      Cron Backups
###########################################################

my $cron;

my $game_settings = readFromDB(
        table    => 'games',
        column   => 'name',
        hash_ref => 'true'
    );

my $user_settings = readFromDB(
        table    => 'users',
        column   => 'username',
        hash_ref => 'true'
    );

my $perms = readFromDB(
        table    => 'perms',
        column   => 'username',
        hash_ref => 'true'
    );

foreach my $game (keys %{$game_settings}) {
    $cron = $game_settings->{$game}{'crontab'} or $cron = int(rand(5)) . ' * * * *'; #int(rand(5) + 10)
    app->log->info("scheduling backup for $game $cron");

    plugin Cron => ( $game => {crontab => $cron, code => sub {
        app->minion->enqueue( store => [$game], { attempts => 1, expire => 120 } );
     } } );
}


###########################################################
##    Authentication
###########################################################

app->sessions->default_expiration( $config->{'session_time'} * 60 * 60 );

app->yancy->plugin(
    'Auth::Password' => {
        schema          => 'users',
        allow_register  => $config->{'allow_registration'},
        username_field  => 'username',
        email_field     => 'email',
        password_field  => 'password',
        password_digest => {
           type => 'SHA-512'
        }
    }
);

group {
    my $route = under '/minion' => sub {
    my $c  = shift;
       my $name = $c->yancy->auth->current_user || '';
        if ( $name ne '' ) {
            my $ip          = $c->remote_addr;
            my $username    = $c->yancy->auth->current_user->{'username'};
            my $is_admin    = $perms->{$username}{'admin'};

            return 1 if ( $is_admin eq '1' );

            $c->res->headers->www_authenticate('Basic');
            $c->flash( error => "you dont have permission to do that " );
            app->log->warn("IDS: $username from $ip requested minions ");
            $c->redirect_to('/');
        };

        $c->redirect_to("/login");
    };
    plugin 'Minion::Admin' => { route => $route };
};

group {
    my $route = under '/status' => sub {
        my $c  = shift;
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


under sub {
    my $c  = shift;
    # Authenticated
    my $name = $c->yancy->auth->current_user || '';
    if ( $name ne '' ) {
         return 1;
    }
    # Security log authentication attempts
    my $ip = $c->remote_addr;

    app->log->warn("AUTH attempt from $ip");
    $c->flash( error => "your ip $ip is logged" );

    $c->stash(
        is_admin => '',
        username => '',
        pool     => '' );

    $c->render( template => 'login' );

    return;
};

###########################################################
##  Minion Routes
###########################################################


get '/update/:game/:node' => sub {
    my $c  = shift;
    my $task        = 'update';
    my $game        = $c->stash('game');
    my $node        = $c->stash('node');
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};

    if ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' ) {
        $c->minion->enqueue( $task => [$game], { attempts => 1, expire => 120 } );
        $c->flash( message => "sending minions to $task $game on $node " );
        app->log->info("$username from $ip initiated $task $game on $node" );
    }
    else {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("$username from $ip attempted to $task $game ");
    };
    $c->redirect_to($c->req->headers->referrer);
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

## BootStrap   #################################################

get '/bootstrap/:game/:node' => sub {
    my $c  = shift;
    my $task        = 'bootstrap';
    my $game        = $c->stash('game');
    my $node        = $c->stash('node');
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};

    if ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' ) {
        $c->minion->enqueue( $task => [$game], { attempts => 1, expire => 120 } );
        $c->flash( message => "sending minions to $task $game on $node " );
        app->log->info("$username from $ip initiated $task $game on $node" );
    }
    else {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("$username from $ip attempted to $task $game ");
    };
    $c->redirect_to($c->req->headers->referrer);
};
app->minion->add_task(
    bootstrap => sub ( $job, $game ) {
        my $task = 'bootstrap';
        my $lock = $game;

        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"} )
          unless app->minion->lock( $lock, 300 );

        my $bootstrap = bootStrap( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '1_bootstrap' => "$game $bootstrap" );

        my $update = update( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '2_update' => "$game $update" );

        my $boot = bootGame( game => $game, server_bin => $update, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '3_boot' => "$game $boot" );

        sleep(60);

        my $halt = haltGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '4_halt' => "$game $halt" );

        my $rebootstrap = bootStrap( game => $game, server_bin => $update, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '5_bootstrap' => "$game $rebootstrap" );

        my $reboot = bootGame( game => $game, server_bin => $update, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '6_boot' => "$game $reboot" );

        my $regist = registerGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '7_register' => "$game $regist" );

        $job->app->log->info("$task $game completed");

        unless ( $reboot ) {
            $job->finish( { message => "$task $game completed" } );
        }
        else {
            $job->fail( { message => "$task $game failed" } );
        }
        app->minion->unlock($lock);
    }
);


## Boot   #################################################

get '/boot/:game/:node' => sub {
    my $c  = shift;
    my $task        = 'boot';
    my $game        = $c->stash('game');
    my $node        = $c->stash('node');
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};

    if ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' ) {
        $c->minion->enqueue( $task => [$game], { attempts => 1, expire => 120 } );
        $c->flash( message => "sending minions to $task $game on $node " );
        app->log->info("$username from $ip initiated $task $game on $node" );
    }
    else {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("$username from $ip attempted to $task $game ");
    };
    $c->redirect_to($c->req->headers->referrer);
};
app->minion->add_task(
    boot => sub ( $job, $game ) {
        my $task = 'boot';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 300 );

        my $deploy = deployGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '1_deploy' => "$game $deploy" );

        my $update = update( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '2_update' => "$game $update" );

        my $boot = bootGame( game => $game, server_bin => $update, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '3_boot' => "$game $boot" );

        my $regist = registerGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '4_register' => "$game $regist" );

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

get '/halt/:game/:node' => sub {
    my $c  = shift;
    my $task        = 'halt';
    my $game        = $c->stash('game');
    my $node        = $c->stash('node');
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};

    if ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' ) {
        $c->minion->enqueue( $task => [$game], { attempts => 1, expire => 120 } );
        $c->flash( message => "sending minions to $task $game on $node " );
        app->log->info("$username from $ip initiated $task $game on $node" );
    }
    else {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("$username from $ip attempted to $task $game ");
    };
    $c->redirect_to($c->req->headers->referrer);
};
app->minion->add_task(
    halt => sub ( $job, $game ) {
        my $task = 'halt';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 60 );

        $job->app->log->info("Job: $task $game begins");

        my $store = storeGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '1_store' => "$game $store" );
        my $halt = haltGame( game => $game, ssh_master    => $config->{'minion_ssh_master'} );
        $job->note( '2_halt' => "$game $halt" );

        $job->app->log->info("$task $game completed");
        $job->finish( { message => "$task $game completed" } );

        app->minion->unlock($lock);
    }
);

## Deploy #################################################

get '/deploy/:game/:node' => sub {
    my $c  = shift;
    my $task        = 'deploy';
    my $game        = $c->stash('game');
    my $node        = $c->stash('node');
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};

    if ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' ) {
        $c->minion->enqueue( $task => [$game], { attempts => 1, expire => 120 } );
        $c->flash( message => "sending minions to $task $game on $node " );
        app->log->info("$username from $ip initiated $task $game on $node" );
    }
    else {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("$username from $ip attempted to $task $game ");
    };
    $c->redirect_to($c->req->headers->referrer);
};
app->minion->add_task(
    deploy => sub ( $job, $game ) {
        my $task = 'deploy';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 300 );

        $job->app->log->info("Job: $task $game begins");

        my $output = deployGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '1_deploy' => "$game $output" );

        $job->app->log->info("$task $game completed");
        $job->finish(
            { message => "$task $game completed" } );
        app->minion->unlock($lock);
    }
);

## Store #################################################

get '/store/:game/:node' => sub {
    my $c  = shift;
    my $task        = 'store';
    my $game        = $c->stash('game');
    my $node        = $c->stash('node');
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};

    if ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' ) {
        $c->minion->enqueue( $task => [$game], { attempts => 1, expire => 120 } );
        $c->flash( message => "sending minions to $task $game on $node " );
        app->log->info("$username from $ip initiated $task $game on $node" );
    }
    else {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("$username from $ip attempted to $task $game ");
    };
    $c->redirect_to($c->req->headers->referrer);
};
app->minion->add_task(
    store => sub ( $job, $game ) {

        my $task = 'store';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 300 );

        $job->app->log->info("Job: $task $game begins");

        my $output = storeGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '1_store' => "$game $output" );

        $job->app->log->info("$task $game completed");
        $job->finish(
            { message => "$task $game completed" } );
        app->minion->unlock($lock);
    }
);

## Link ###################################################

get '/link/:game/:node' => sub {
    my $c  = shift;
    my $task        = 'link';
    my $game        = $c->stash('game');
    my $node        = $c->stash('node');
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};

    if ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' ) {
        $c->minion->enqueue( $task => [$game], { attempts => 1, expire => 120 } );
        $c->flash( message => "sending minions to $task $game on $node " );
        app->log->info("$username from $ip initiated $task $game on $node" );
    }
    else {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("$username from $ip attempted to $task $game ");
    };
    $c->redirect_to($c->req->headers->referrer);
};
app->minion->add_task(
    link => sub ( $job, $game ) {
        my $task = 'link';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 10 );

        $job->app->log->info("Job: $task $game begins");

        my $output = registerGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '1_register' => "$game $output" );

        $job->app->log->info("$task $game completed");
        $job->finish( { message => "$task $game completed" } );
        app->minion->unlock($lock);
    }
);

## Drop #################################################

get '/drop/:game/:node' => sub {
    my $c  = shift;
    my $task        = 'drop';
    my $game        = $c->stash('game');
    my $node        = $c->stash('node');
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};

    if ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' ) {
        $c->minion->enqueue( $task => [$game], { attempts => 1, expire => 120 } );
        $c->flash( message => "sending minions to $task $game on $node " );
        app->log->info("$username from $ip initiated $task $game on $node" );
    }
    else {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("$username from $ip attempted to $task $game ");
    };
    $c->redirect_to($c->req->headers->referrer);
};
app->minion->add_task(
    drop => sub ( $job, $game ) {
        my $task = 'drop';
        my $lock = $game;
        return $job->fail({ message => "Previous job $task for $game is still active. Refusing to proceed"})
          unless app->minion->lock( $lock, 10 );

        $job->app->log->info("Job: $task $game begins");

        my $output = deregisterGame( game => $game, ssh_master  => $config->{'minion_ssh_master'} );
        $job->note( '1_deregister' => "$game $output" );

        $job->app->log->info("$task $game completed");
        $job->finish( { message => "$task $game completed" } );
        app->minion->unlock($lock);
    }
);

###########################################################
##          Routing
###########################################################

get '/' => sub {
    my $c  = shift;
    my $network = checkIsOnline(
        list_by => 'node',
        node    => '',
        game    => '',
        ssh_master => $config->{'ssh_master'},
    );

    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};
    my $pool        = $perms->{$username}{'pool'};

    $c->stash(
        title    => 'network overview',
        network  => $network,
        perms    => $perms,
        expected => $game_settings,
        is_admin => $is_admin,
        username => $username,
        pool     => $pool,
        list     => ''
    );

    #$c->render( json => $network );
    $c->render( template => 'index' );
};


get '/pool' => sub {
    my $c  = shift;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};
    my $pool        = $perms->{$username}{'pool'};

    my $network     = checkIsOnline(
        list_by     => 'node',
        ssh_master  => $config->{'ssh_master'}
    );

    my $jobs = app->minion->jobs(
        {
            queues => ['default'],
            states => [ 'active', 'locked' ],
            tasks  => [ 'boot',   'halt' ]
        }
    );

    my $locks = getMinionLocks();

    $c->stash(
        network     => $network,
        history     => $jobs,
        perms       => $perms,
        is_admin    => $is_admin,
        username    => $username,
        pool        => $pool,
        locks       => $locks
    );

    $c->render(
        template    => 'pool',

    );
};

get '/info/:node/' => sub {
    my $c  = shift;
    my $template    = 'node_details';
    my $node        = $c->stash('node');

    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};
    my $pool        = $perms->{$username}{'pool'};

    unless ( $is_admin eq '1' ) {
        $c->flash( error => "you dont have permission to do that " );
        app->log->warn("IDS: $username from $ip requested $template $node ");
        $c->redirect_to($c->req->headers->referrer);
    };

    my $results     = infoNode( node => $node, ssh_master => $config->{'ssh_master'} );

    $c->stash(
        results     => $results,
        is_admin    => $is_admin,
        username    => $username,
        pool        => $pool
    );
    $c->render( template => $template );
};

get '/node/:node' => sub {
    my $c  = shift;
    my $node        = $c->stash('node');

    my $network     = checkIsOnline(
        list_by     => 'node',
        node        => $node,
        game        => '',
        ssh_master  => $config->{'ssh_master'}
    );

    if ( $network->{'nodes'}{$node}{'status'} ne 'online' ) {
        $c->flash(error => "$node doesn't exist");
        $c->redirect_to("/");
    };

    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};
    my $pool        = $perms->{$username}{'pool'};

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

    my $locks = getMinionLocks();

    $c->render(
        template    => 'node',
        network     => $network,
        history     => $jobs,
        expected    => $expected,
        perms       => $perms,
        is_admin    => $is_admin,
        username    => $username,
        pool        => $pool,
        locks       => $locks
    );
};


websocket '/filemanager/<game>-ws' => sub {

    my $self        = shift;
    my $game        = $self->stash('game');
    my $ip          = $self->remote_addr;
    my $username    = $self->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};
    my $pool        = $perms->{$username}{'pool'};

    app->log->info("opening $game filemanager for $username from $ip ");

    return unless ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' );

    my $settings    = readFromDB(
        table       => 'games',
        column      => 'name',
        hash_ref    => 'true'
    );

    my $sip = readFromDB(
        table       => 'nodes',
        column      => 'ip',
        field       => 'name',
        value       => $settings->{$game}{'store'},
        hash_ref    => 'false'
    );

    my $store       = $settings->{$game}{'store'};
    my $store_path  = $settings->{$game}{'store_path'};
    my $store_user  = $settings->{$game}{'store_usr'};
    my $home_dir    = $settings->{$game}{'store_path'};
    my $path = '/' . $game;
    my @files;

    $self->inactivity_timeout(1800);
    $self->tx->with_compression;

    my $ssh = connectSSH( user => $store_user, ip => $sip, ssh_master => 'false' );
    return 1 if $ssh->{'error'};


    my $browser = sub {
        my ($c, $hash) = @_;
        my $content = '';
        my %file_content;

        # Strip out any double dots
        $hash->{path} =~ s/\.*$//g if $hash->{path};
        $path = $hash->{base_dir} if ( $hash->{base_dir} );
        my $encoded_path = url_escape $path;
        app->log->debug("$game path: $path");

        my $ls_cmd      = qq([ -d '$home_dir/$path' ] && cd '$home_dir/$path' && );
           $ls_cmd     .=  q(stat * .* --format '%F,%n,%Y,%s,%w,%y' | sort -k1 -k2 -k3);

        my $files       = $ssh->{'link'}->capture("$ls_cmd") ; #if $hash->{path};

        my $file_cmd    = qq([ -d '$home_dir/$path' ] && cd '$home_dir/$path' );
           $file_cmd   .= qq(&& find * -maxdepth 0 -type f -exec grep -IlH . {} + );
           $file_cmd   .= qq(| xargs -d '\n' head -v -n 15);

        my $head        =  $ssh->{'link'}->capture("$file_cmd");
           $head        =~ s/\n/<newline>/g;

           app->log->trace("$game heads: $head");

        my $num;
        foreach ( split '==> ', $head ) {
        ++$num;
         my ($filename, $line_content) =  (split ' <==', $_ );
            next unless $filename;
            $file_content{$filename}   =  $line_content;
            $file_content{$filename}   =~ s/<newline>/\n/g;
            $file_content{$filename}   =~ s/>/\&gt;/g;
            $file_content{$filename}   =~ s/</\&lt;/g;
        }

        $content  = q(<nav style="--bs-breadcrumb-divider: '>';" aria-label="breadcrumb"><ol class="breadcrumb">);

        my @breadcrumbs = ( split '/', $path );
        my $combined_crumbs;

        foreach ( @breadcrumbs ) {
            next if ( $_ =~ m/^$/ );

            $combined_crumbs .= '/' . $_;
            $content .= qq(
            <li class="breadcrumb-item text-primary"
                 type="submit" onclick="browser_path('$combined_crumbs')">
                $_
            </li>
            );
        }

        $content .= q(</ol> </nav><hr>);
        $content .= q(<div class="container"><div class="row">);

        foreach my $line ( split '\n',  $files ) {
            my $color = 'light';
            my $icon = q(bi-question-square);
            my ($type, $filename, $epoc, $size, $created, $modified) = split( ',', $line );
            $size = format_bytes $size ;

            my $encoded_file_link = $path . '/' . $filename;
               $encoded_file_link = url_escape $encoded_file_link;

            if ( $filename =~ m/[0-9]+[MKG]$/ ) { next }
            if ( $filename =~ m/\.+$/ ) { next }
            if ( $filename =~ m/txt$/ )  { $icon = q(bi-filetype-txt);   }
            if ( $filename =~ m/jar$/ )  { $icon = q(bi-filetype-java);  }
            if ( $filename =~ m/json$/ ) { $icon = q(bi-filetype-json);  }
            if ( $filename =~ m/yml$/ )  { $icon = q(bi-filetype-yml); $color = 'green'   }
            if ( $filename =~ m/txt$/ )  { $icon = q(bi-filetype-txt);   }
            if ( $filename =~ m/sh$/ )   { $icon = q(bi-filetype-sh);    }
            if ( $filename =~ m/log[.0-9]*$/ )  { $icon = q(bi-journal-bookmark);   }
            if ( $filename =~ m/sql$/ )  { $icon = q(bi-filetype-sql);   }
            if ( $filename =~ m/png$/ )  { $icon = q(bi-filetype-png);   }
            if ( $filename =~ m/rc$/ )   { $icon = q(bi-gear);           }
            if ( $filename =~ m/gz$/ )  { $icon = q(bi-file-earmark-zip);   }

            if ( $line =~ m/json"$/ && $file_content{$filename} ne '' ) {
             $file_content{$filename} =~ s/":"/" => "/g;
             $file_content{$filename} =~ s/,([^{])/,\n    $1/g;
             $file_content{$filename} =~ s/,\{/,\n\{/g;
             $file_content{$filename} =~ s/\{/\{\n    /g;
             $file_content{$filename} =~ s/}/\n}/g;
             $file_content{$filename} =~ s/\n[ \t]*\n/\n/g;
            }

            my $id = '';
            for my $i (0..10) {
                $id .= chr(rand(25) + 97);
            }

            app->log->trace("id: $filename -> $id");

            my $preview = 'binary file or preview unavailable';
            if ( defined $file_content{$filename} ) {
                $preview = qq(
                    <h6>preview:</h6>
                    <div class="bg-success p-1 text-dark bg-opacity-10 rounded border border-success shadow"
                        style="--bs-border-opacity: .5;">
                        <pre>$file_content{$filename}</pre>
                    </div>
                );
            }

            if ( $type =~ m/^directory/ ) {
                $icon = q(bi-folder-fill); $color = 'green';
                $content .= qq(
                <span class="col-md-4">
                    <button class="btn" data-bs-target="#$id style="text-align: start; text-indent: -1.1em; padding-left: 2.85em;"
                     type="submit" id="$id" value="$path/$filename" onclick="browser_path('$path/$filename')">
                    <i class="bi $icon" style="font-size: 1.75rem; color: $color;"></i>
                    $filename
                    </button>
                </span>
               );
            }
            else {
            my $modal = 'editor_m';
            my $label = 'editor_label';
            $content .= qq(
                <span class="col-md-4">
                    <button class="btn" type="button" data-bs-toggle="offcanvas" data-bs-target="#$id"
                        aria-controls="$id" style="text-align: start; text-indent: -1.1em; padding-left: 2.85em;">
                    <i class="bi $icon zoom" style="font-size: 1.75rem; color: $color;"></i>
                    $filename
                    </button>
                  <div class="offcanvas offcanvas-start" style="width: 750px;" tabindex="-1" id="$id"
                        aria-labelledby="$id">
                    <div class="offcanvas-header d-flex justify-content-between">
                        <h5 class="offcanvas-title align-bottom flex-grow-1" id="$id">
                        <i class="bi $icon" style="font-size: 2.5rem; color: green;"></i> $filename </h5>

                        <button class="btn btn-sm btn-outline-danger m-1" type="button" data-bs-dismiss="offcanvas"
                                style="width: 100px !important;" onclick="delete_file('$encoded_file_link')">
                            delete
                        </button>
                        );

                         if ( defined $file_content{$filename} ) {
                        $content .= qq(
                        <!-- Button trigger modal -->
                        <button class="btn btn-sm btn-outline-secondary m-1" data-bs-toggle="modal"
                                data-bs-dismiss="offcanvas" data-bs-target="#editor_m" style="width: 100px !important;"
                                onclick="edit_file('$encoded_file_link')" >
                          edit
                        </button>
                        );
                        }

                        $content .= qq(
                        <button class="btn btn-sm btn-outline-primary m-1" type="button" data-bs-dismiss="offcanvas"
                                style="width: 100px !important;" onclick="get_file('$encoded_file_link')">
                          download
                        </button>

                        <button type="button" class="btn-close" data-bs-dismiss="offcanvas" aria-label="Close"></button>
                    </div>
                    <div class="offcanvas-body">
                        <div>
                           <h6>folder: $path</h6>
                           <h6>size: $size</h6>
                           <h6>created: $created</h6>
                           <h6>modified: $modified</h6>
                           <hr>
                            $preview
                        </div>
                    </div>
                  </div>
                 </span>
                    );
              }
        }
        $content .= qq(
            </div></div>
            <div class="mt-3 shadow accordion" id="accordionExample">
                <div class="accordion-item">
                    <h2 class="accordion-header" id="headingOne">
                        <button class="accordion-button" type="button" data-bs-toggle="collapse"
                          data-bs-target="#collapseOne" aria-expanded="true" aria-controls="collapseOne">
                            upload files
                        </button>
                    </h2>
                    <div id="collapseOne" class="accordion-collapse collapse" aria-labelledby="headingOne"
                      data-bs-parent="#accordionExample">
                        <div class="accordion-body bg-light ">
                            <hr>
                              <form id="upload_form" enctype="multipart/form-data" method="post">
                              <input name="folder" type="hidden" value="$encoded_path">
                              <input type="file" name="filelist" id="filelist" onchange="uploadFile('$encoded_path')" multiple/><br>
                              <hr>
                              <!-- progress bars container -->
                                <div id="dynamic_progress"></div>
                             <!-- <progress id="progressBar" value="0" max="100" style="width:50%;"></progress> -->
                              <p id="status"></p>
                              <p id="loaded_n_total"></p>
                              <p id="upload_results"></p>
                              <output></output>
                           </form>
                        </div>
                    </div>
                </div>
            </div>
            <script> var here='$combined_crumbs'; <script>
        );

        $content = encode_json{ base_dir => $content };
        $self->send("$content");
    };


    my $get_file = sub {
        my ($c, $hash) = @_;

        app->log->info("file download requested");

        my $file = $hash->{get_file} if ( $hash->{get_file} );
           $file = url_unescape $file;

        app->log->info("file: $home_dir/$file");

        my @folders  =  (split '/', $file );
        my $filename =  $folders[-1];
           #$filename =~ s/ /_/g;
        my $filepath = $file;
           $filepath =~ s/[^\/]+$//;

        my $id = '';
        for my $i (0..10) {
            $id .= chr(rand(25) + 97);
        }

        # $Net::OpenSSH::debug = ~0;
        my $path = path("tmp/$id")->make_path;

        my $cmd = qq(cd '$home_dir$filepath'; tar cf - '$filename');
        my $remote = $ssh->{'link'}->make_remote_command($cmd);
        system "$remote | tar xvf - -C tmp/$id  ";

        my $encoded = $id . '/' . $filename;
           $encoded = b64_encode $encoded;

        app->log->info("$encoded");
        $self->send( encode_json{ path => "download", filename => $encoded } ) ;
       # $self->send( $content ) if $content;
    };

    my $delete_file = sub {
        my ($c, $hash) = @_;

        app->log->info("file delete requested");

        my $file = $hash->{delete_file} if ( $hash->{delete_file} );
           $file = url_unescape $file;

        app->log->warn("delete file: $home_dir/$file");

        my @folders  =  (split '/', $file );
        my $filename =  $folders[-1];
           #$filename =~ s/ /_/g;
        my $filepath = $file;
           $filepath =~ s/[^\/]+$//;

        my $cmd = qq(cd "$home_dir$filepath"; rm "$filename");
           $ssh->{'link'}->system($cmd);

            $browser->();
    };

    my $load_editor_content = sub {
        my ($c, $hash) = @_;

        app->log->info("file edit requested");

        my $file = $hash->{file_path} if ( $hash->{file_path} );
           $file = url_unescape $file;

        app->log->debug("file: $home_dir + $file");

        my $filename = ( split '/', $file )[-1];
        my $filepath = $file =~ s/[^\/]+$//r;

        app->log->debug("$filepath: $filename");

        # $Net::OpenSSH::debug = ~0;
        my $id = '';
        for my $i (0..10) {
            $id .= chr(rand(25) + 97);
        }

        my $path    = path("tmp/$id")->make_path;
        my $cmd     = qq(cd '$home_dir$filepath'; tar --no-wildcards -cf - '$filename');
        my $remote  = $ssh->{'link'}->make_remote_command($cmd);
        system "$remote | tar xvf - -C tmp/$id  ";

        open my $fh, '<', "tmp/$id/$filename";
             my $content = do { local $/; <$fh> };
        close $fh;
            app->log->trace("file: $content");

        $self->send( encode_json{ editor_content => $content } ) if $content;

        $path->remove_tree({keep_root => 1}, "tmp/$id");
    };

    my $save_editor_content = sub {
        my ($c, $hash) = @_;

        app->log->info("file save requested");

        my $file    = $hash->{file_path} if ( $hash->{file_path} );
           $file    = url_unescape $file;
        my $content = $hash->{save_editor_content};

        app->log->debug("file: $home_dir + $file");
        app->log->debug($content);

        my $filename    = ( split '/', $file )[-1];
        my $filepath    = $file =~ s/[^\/]+$//r;
        my $store_path  = $home_dir . $filepath;

        app->log->info("$store_path/$filename");

        my $id = '';
        for my $i (0..10) {
            $id .= chr(rand(25) + 97);
        }

        my $path = path("tmp/$id")->make_path;
            open my $fh, '>', $path . "/" . $filename;
            print {$fh} $content;
            close $fh;

        #system "echo $content | base64 - -d > $path/$filename";

        my $cmd = qq( tar xvf - -C '$store_path' );
        my $remote_cmd   = $ssh->{'link'}->make_remote_command($cmd);
        my $combined_cmd = qq(cd '$path'; tar cf - '$filename' | $remote_cmd );

        system "$combined_cmd";

        app->log->trace("cd $path; tar cf - $filename | $remote_cmd");

        $path->remove_tree({keep_root => 1}, "tmp/$id");

    };

    $self->on(json => sub {
        my ($c, $hash) = @_;
        app->log->debug("incoming websocket request");
        my $bugs = Dumper($hash);
        app->log->trace("$bugs");

         $browser->($c, $hash) if $hash->{base_dir};
         $get_file->($c, $hash) if $hash->{get_file};
         $delete_file->($c, $hash) if $hash->{delete_file};
         $load_editor_content->($c, $hash) if $hash->{load_editor_content};
         $save_editor_content->($c, $hash) if $hash->{save_editor_content};
    });

    $self->on(finish => sub ($ws, $code, $reason) {
        app->log->debug("WebSocket closed with status $code.");
    });

    $browser->();
};

get '/filemanager/:game'  => sub {
    my $c  = shift;
    my $template    = 'filemanager';
    my $game        = $c->stash('game');
    my $node        = $c->stash('node');
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};
    my $pool        = $perms->{$username}{'pool'};

    unless ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' ) {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("IDS: $username from $ip requested $template $game ");
        $c->redirect_to($c->req->headers->referrer);
    };
    app->log->info("filemanager $game ");

    $c->stash(
        is_admin    => $is_admin,
        username    => $username,
        pool        => $pool,
        game        => $game
     );
    $c->render( template => $template );
};


get '/download/:id' => sub {
    my $self        = shift;
    my $ip          = $self->remote_addr;
    my $username    = $self->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};
    my $id          = $self->stash('id');


   return unless ( $username );
   $id = b64_decode $id;

    # Sanitise path to prevent /../ or /./ dots travelling outside tmp dir
    $id =~ s|/\.+/|/|g;

   my $path = path("tmp/$id");
        app->log->info("download route: $id");

   my $filename =  $path->basename;
   my $filepath =  $id;
      $filepath =~ s/[^\/]+$//;

      $self->res->headers->content_disposition("attachment; filename=$filename;");
      $self->reply->file(app->home->child('tmp', "$id"));

      $path->remove_tree({keep_root => 1}, "tmp/$filepath");
        app->log->info("path: $path");
};


get '/reload' => sub {
    my $c  = shift;
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};

    unless ( $is_admin eq '1') {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("IDS: $username from $ip requested a reload ");

        $c->redirect_to('/');
    };

    my $ppid = getppid();
    kill 'USR2' => $ppid;
    sleep(1);
    $c->flash(message => "reload signal sent to $ppid");
    $c->redirect_to('/');
    #$c->redirect_to($c->req->headers->referrer);
};


get '/logfile' => sub {
    my $c  = shift;
    my $template    = 'logfile';
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};
    my $pool        = $perms->{$username}{'pool'};

    unless ( $is_admin eq '1' ) {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("IDS: $username from $ip requested $template ");
        $c->redirect_to($c->req->headers->referrer);
    };

    $c->stash(
        username    => $username,
        is_admin    => $is_admin,
        pool        => $pool
    );

    app->log->debug("retrieving logfile");
    $c->render( template => $template, perms => $perms );
};


websocket '/logfile-ws' => sub {

    my $self = shift;

    my $username    = $self->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};

    return unless $is_admin;

    my $line_index;

    my $file = app->log->path;
    my $results;

    my $game;
    my $ip;
    my $user;
    my $loop;

    $self->inactivity_timeout(1800);
    $self->tx->with_compression;

    app->log->debug("reading logfile via websocket");

    my $send_data;
    $send_data = sub {
        $results = updatePage(
                    file        => $file,
                    line_index  => $results->{'line_index'},
                    ip          => $ip,
                    user        => $user,
                    game        => $game,
                 );

        if ( $results->{'new_content'} ) {
            my $content;
            foreach ( split( /\n/, ( $results->{'new_content'} ) ) ) {
                ++$line_index;
                $content = '<div>' . $_ . "</div>\n" . $content;
            }
            $self->send( $content );
        }
    };

    $self->on(finish => sub ($ws, $code, $reason) {
        app->log->debug("WebSocket closed with status $code.");
        Mojo::IOLoop->remove($loop);
    });

    $send_data->();
    $loop = Mojo::IOLoop->recurring( 1, $send_data );
};


get '/serverlog/:task' => sub {
    my $c  = shift;
    my $task        = $c->stash->{'task'};
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};

    unless ( $is_admin eq '1' ) {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("IDS: $username from $ip requested serverlog $task");

        $c->redirect_to($c->req->headers->referrer);
    };

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

    my $self = shift;
    my $ip          = $self->remote_addr;
    my $username    = $self->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};
    my $node        = $self->stash('node');
    my $game        = $self->stash('game');

    return unless ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' );

    my $loop;

    $self->inactivity_timeout(1800);
    $self->tx->with_compression;

    app->log->info("opening websocket for $username to read $game logfile on $node");

    my $send_data;
    my $line_index;
    my $logdata;
    my $screenlog;

    $send_data = sub {

        app->log->debug("$$ websocket: polling $game on $node ");

           $logdata     = readLog(
            node        => $node,
            game        => $game,
            line_index  => $line_index,
            screenlog   => $screenlog,
            ssh_master  => $config->{'ssh_master'}
        );

        my $content;

        foreach ( split( /\n/, ( $logdata->{'content'} ) ) ) {
            ++$logdata->{'line_index'};                                 # Index hardcopy.
        };

        # Now fix wrapped lines for formatting
        $logdata->{'content'} =~ s/([^\n]{79})\n/$1/g;                  # Vertial term wraps at 80 characters
        $logdata->{'content'} =~ s/([^\n]{60})(\[[0-9:]{8})/$1\n$2/g;   # Newline for log timestamps

        foreach ( split( /\n/, ( $logdata->{'content'} ) ) ) {
            $content = "<div>" . $_ . "</div>\n" . $content if $_;
        };
        $logdata->{'content'} = '';
        $screenlog = $logdata->{'screenlog'};
        $line_index = $logdata->{'line_index'};
        $self->send( $content ) if $content;

   };

    $self->on(json => sub {
         my ($c, $hash) = @_;

         # Strip out any command characters
         $hash->{cmd} =~ s/[\^\\]//g;

         sendCommand(   command     => $hash->{cmd},
                        game        => $game,
                        node        => $node,
                        ssh_master  => $config->{'minion_ssh_master'}
         ) if $hash->{cmd};

         app->log->info("$username sent console command to $game on $node:");
         app->log->info(" # $hash->{cmd}");
         Time::HiRes::sleep( 0.2 );

         $send_data->();
    });

    $self->on(finish => sub ($ws, $code, $reason) {
        app->log->info("WebSocket closed with status $code.");
        Mojo::IOLoop->remove($loop);
    });

    $send_data->();
    $loop = Mojo::IOLoop->recurring($config->{'poll_interval'} => $send_data);
};


get '/log/:node/:game' => sub {
    my $c  = shift;
    my $template    = 'gamelog';
    my $game        = $c->stash('game');
    my $node        = $c->stash('node');
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};
    my $pool        = $perms->{$username}{'pool'};

    unless ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' ) {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("IDS: $username from $ip requested $template $game ");
        $c->redirect_to($c->req->headers->referrer);
    };

    app->log->debug("reading $game logfile");

    $c->stash(
        node        => $node,
        game        => $game,
        is_admin    => $is_admin,
        username    => $username,
        pool        => $pool
    );

    $c->render(
        template => $template
    );
};


# Multipart upload handler
post '/upload' => sub {
    my $c  = shift;
    # Check file size
    return $c->render(text => 'File is too big.', status => 200) if $c->req->is_limit_exceeded;
    return $c->redirect_to($c->req->headers->referrer) unless my $file = $c->param('file');


    # print Dumper($c->param());
    my $size        = $file->size;
    my $name        = $file->filename;
    my $target_path = url_unescape $c->param('folder');

    my $game  = (split '/', $target_path)[1];

    #my $game        = $parse_path[1];
    my $ip          = $c->remote_addr;
    my $username    = $c->yancy->auth->current_user->{'username'};
    my $is_admin    = $perms->{$username}{'admin'};
    my $pool        = $perms->{$username}{'pool'};

    unless ( $game_settings->{$game}{'pool'} eq $perms->{$username}{'pool'} || $is_admin eq '1' ) {
        $c->flash( error => "you dont have permission to do that" );
        app->log->warn("IDS: $username from $ip requested upload");
        $c->redirect_to($c->req->headers->referrer);
    };

    app->log->info("$username uploading $name $size to $target_path");

    my $settings    = readFromDB(
        table       => 'games',
        column      => 'name',
        hash_ref    => 'true'
    );

    my $sip = readFromDB(
        table       => 'nodes',
        column      => 'ip',
        field       => 'name',
        value       => $settings->{$game}{'store'},
        hash_ref    => 'false'
    );

    my $store       = $settings->{$game}{'store'};
    my $store_path  = $settings->{$game}{'store_path'};
    my $store_user  = $settings->{$game}{'store_usr'};
    my $home_dir    = $settings->{$game}{'store_path'};

    my $id = '';
    for my $i (0..10) {
        $id .= chr(rand(25) + 97);
    }

    my $ssh = connectSSH( user => $store_user, ip => $sip, ssh_master => 'false' );
    return 1 if $ssh->{'error'};

        # $Net::OpenSSH::debug = ~0;
    my $path = path("tmp/$id")->make_path;
       $file->move_to( $path . '/' . $name );

    my $cmd = qq( tar xvf - -C "$store_path/$target_path" );
        my $remote_cmd   = $ssh->{'link'}->make_remote_command($cmd);
        my $combined_cmd = qq(cd "$path"; tar cf - "$name" | $remote_cmd );
        system "$combined_cmd";

        app->log->trace("cd $path; cd $path; tar cf - $name | ssh $cmd");

        $path->remove_tree({keep_root => 1}, "tmp/$id");

        $size = format_bytes( $size );
        $c->render(text => "received: $name: $size<br>");
};


any '*' => sub {
    my $c  = shift;
    my $url = $c->req->url->to_abs;
    my $ip  = $c->remote_addr;
    my $user = $c->yancy->auth->current_user->{'username'};
    app->log->warn("IDS: $user \[$ip\] $url");
    $c->flash( error => "page doesn't exist" );
    $c->redirect_to("/");
};

websocket '/notify' => sub {
    my $c  = shift;

};

###########################################################
##    Functions
###########################################################

sub getMinionLocks {

    my $minion_locks = {};
    my $results = app->minion->backend->list_jobs(0, 100, {states => ['inactive', 'active']} );

    if (@{$results->{jobs}}) {
        for my $job (@{$results->{jobs}}) {
            $minion_locks->{$job->{args}[0]} = 'true';
        }
    }
    return $minion_locks;
}

sub updatePage_game {
    my %args = (
       line_index   => '',
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

        #if ( $iteration > $args{'line_index'} ) {
            ++$args{'line_index'};
            $new_content = $new_content . '<div>' . $_ . "</div>\n";
        #}
    }

    $args{'iteration'}   = $iteration;
    $args{'new_content'} = $new_content;

    return \%args;
}


sub updatePage {
    my %args = (
       line_index   => '',
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

        if ( $iteration > $args{'line_index'} ) {
            ++$args{'line_index'};
            $new_content = $new_content . "<div>" . $_ . "</div>\n";
        }
    }

    close (FILE);

    $args{'iteration'}   = $iteration;
    $args{'new_content'} = $new_content;

    return \%args;
}

sub update {
    my %args        = (
        game        => '',
        node        => '',
        ip          => '',
        project     => '',
        release     => '',
        @_,
    );

    my ( $project, $release, $version );

    my $game        = $args{'game'} or return 1;

    my $settings    = readFromDB(
        table       => 'games',
        column      => 'name',
        field       => 'name',
        value       => $game,
        hash_ref    => 'true'
    );
    my $ip          = readFromDB(
        table       => 'nodes',
        column      => 'ip',
        field       => 'name',
        value       => $settings->{$game}{'node'},
        hash_ref    => 'false'
    );

    if ( $settings->{$game}{isBungee} eq '1' ) {
         $project   = 'waterfall';
    }
    else {
        $project    = 'paper';
    }

    $release        = $settings->{$game}{release};

     # Get latest release version
    my $project_url =
        "https://api.papermc.io/v2/projects/$project/versions/$release/";
    my $ua          = Mojo::UserAgent->new();
    my $builds      = $ua->get($project_url)->result->json;

    my $latest      = $builds->{'builds'}[-1];
    my $file_name   = "$project-$release-$latest.jar";

       $project_url = $project_url . '/builds/' . $latest;
    my $meta        = $ua->get("$project_url")->result->json;
    my $sha256      = $meta->{'downloads'}->{'application'}{'sha256'};

    my $path        = $settings->{$game}{'node_path'} . '/'
                    . $game
                    . '/game_files/';

    # Install Latest version
    my $user        = $settings->{$game}{'node_usr'};
    my $ssh         = connectSSH( user => $user, ip => $ip, ssh_master => $args{'ssh_master'} );

    return $ssh->{'error'} if $ssh->{'error'};
    return $ssh->{'debug'} if $ssh->{'debug'};

    $project_url    = $project_url . '/downloads/' . $file_name;
    my $cmd         = 'wget -t 2 -T 30 -c ' . $project_url . ' -O ' . $path . $file_name;

    $ssh->{'link'}->system("$cmd");

    $cmd            = "sha256sum $path/$file_name";
    my @sha_file    = split( / /, $ssh->{'link'}->capture("$cmd") );

    if ( $sha_file[0] eq $sha256 ) {
        return "$file_name";
    }
    else {
        app->log->warn("$game $file_name update failed or was corrupted");

        my $versions = $ssh->{'link'}->capture("cat $path/version_history.json ");
           app->log->debug("$versions");
           $version  = decode_json $versions;

        my $db = Dumper($version);
           app->log->debug("hash: $db");

        my $current_version = lc( $version->{'currentVersion'} );

           # Parse the currentVersion.json file to retrieve previous successful
           # server jar
           # git-Paper-177 (MC: 1.19.2)
           # git-$project-$build (MC: $release)
           # paper-1.19-81.jar

        my ( $git, $project, $build, $cabbage, $release ) = split( /[ :\(\)-]+/, $current_version );
           app->log->warn("rolling back to version: $project-$release-$build.jar ");

        return "$project-$release-$build.jar";
    }
}

sub readLog {
    my %args        = (
        game        => '',
        node        => '',
        @_,
    );
    my $game = $args{'game'} or return 1;
    my $node = $args{'node'} or return 1;

    my $ip = readFromDB(
        table    => 'nodes',
        column   => 'ip',
        field    => 'name',
        value    => $node,
        hash_ref => 'false'
    );

    unless ( $ip ) {
        my $warning = '<div class="alert alert-danger" role="alert">';
        $warning .= '!! WARNING !! <a href="/yancy#/nodes" class="alert-link">';
        $warning .= "$node is miss-configured in the nodes table in database";
        $warning .= '</a></div>';
        return $warning;
    }

    my $settings = readFromDB(
        table    => 'games',
        column   => 'name',
        field    => 'name',
        value    => $game,
        hash_ref => 'true'
    );

    unless ( defined $settings->{$game}{'node_usr'} ) {
        my $warning = '<div class="alert alert-danger" role="alert">';
        $warning .= '!! WARNING !! <a href="/yancy#/games" class="alert-link">';
        $warning .=
          "$game is miss-configured in the games_servers table in database";
        $warning .= '</a></div>';
        return $warning;
    }

    my $ssh = connectSSH( user => $settings->{$game}{'node_usr'}, ip => $ip, ssh_master => $args{'ssh_master'} );

    return $ssh->{'error'} if $ssh->{'error'};
    return $ssh->{'debug'} if $ssh->{'debug'};

    $args{'line_index'} = '1' unless ( $args{'line_index'} );
    app->log->debug("$game log has $args{'line_index'} lines");

    my $method = 'hardcopy';
    my $logfile;

    my $reset = $ssh->{'link'}->capture("screen -ls $game");

    unless ( $reset =~ /There is a screen/ ) {
        $args{'line_index'} = 1;
        $args{'content'} = '';
        app->log->debug("$game screen is offline. $reset");
        $method = 'screenlog';
       #return \%args;
    }

    if ( $method eq 'hardcopy' ) {
        ## Use hardcopy

        $args{'screenlog'} = '';
        $ssh->{'link'}->system("screen -p 0 -S $game -X hardcopy -h");
        Time::HiRes::sleep( 0.2 );

        my  $cmd;
            $cmd  = "[ -f ~/$game/game_files/hardcopy.0 ] && ";
            $cmd .= q(sed -n ');
            $cmd .= $args{'line_index'};
            $cmd .= q(,${$b;p}' < );
            $cmd .= qq($settings->{$game}{'node_path'}/$game/game_files/hardcopy.0);
        app->log->debug($cmd);

           $logfile =  $ssh->{'link'}->capture($cmd);
    }

    if ( $method eq 'screenlog' ) {
        ## Use screenlog.0

     return \%args if ( $args{'screenlog'} eq 'true' );
     $args{'screenlog'} = 'true';

     my @cmd = qq(screen -S $game -X colon "logfile flush 0^M");
        $ssh->{'link'}->system(@cmd);
        Time::HiRes::sleep( 0.5 );

        my  $cmd;
            $cmd  = "[ -f ~/$game/game_files/screenlog.0 ] && ";
            $cmd .= q(tail -n 128 );
            $cmd .= qq($settings->{$game}{'node_path'}/$game/game_files/screenlog.0);

        $logfile .= '#' x 80;
        $logfile .= qq(\n\n## $game is offline, viewing previous log ##\n\n);
        $logfile .= 'v' x 40 . "\n\n";

        $logfile .=  $ssh->{'link'}->capture($cmd);
        $logfile =~ s/\x1b[[()=][;?0-9]*[0-9A-Za-z]?//g;s/\r//g;s/\007//g;

        $logfile .= '^' x 40;
        $logfile .= qq(\n\n## $game is offline, viewing previous log ##\n\n);
        $logfile .= '#' x 80;

        @cmd = qq(screen -S $game -X colon "logfile flush 5^M");
        $ssh->{'link'}->system(@cmd);
    }

   $args{'content'} = $logfile;
   return \%args;
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
                "$config->{'db_user'}",
                "$config->{'db_pass'}",
                {
                    RaiseError => 0,
                    PrintError => 0,
                    AutoCommit => 0
                }
            ) or app->log->warn("cannot connect to the database: $DBI::errstr" );

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

    my $sth = $dbh{$pid}->prepare($query) or app->log->warn("error preparing SQL: $DBI::errstr" );
    $sth->execute() or app->log->warn("error executing SQL: $DBI::errstr" );

    while ( $ref = $sth->fetchrow_hashref() ) {
        my $index_name;
        $index_name = $column unless $index_name = $ref->{$column};

        foreach ( @{ $sth->{NAME} } ) {
            $ref_name                       = $_;
            $ref_value                      = $ref->{$ref_name};
            $result{$index_name}{$ref_name} = $ref_value;
        }
    }

    app->log->warn("error fetching data from DB: $DBI::errstr" ) if $DBI::errstr;

    $dbh{$pid}->disconnect or app->log->warn("error disconnecting from DB: $DBI::errstr" );;

    app->log->debug("DB query complete");

#    app->log->debug("DB error code: ""$dbh{$pid}->errstr");

    if ( $args{'hash_ref'} eq 'true' ) {
        return \%result;
    }
    else {
        return $ref_value;
    }
}


sub checkIsOnline {

    my %args = (
        game            => '',
        node            => '',
        pid             => '',
        user            => $config->{'default_user'},
        list_by         => 'game',
        ssh_master      => '',
        @_,
    );

    my $network = {};

    $network->{'nodes'} = readFromDB(
        table           => 'nodes',
        column          => 'name',
        hash_ref        => 'true'
    );

    $network->{'games'} = readFromDB(
        table           => 'games',
        column          => 'name',
        hash_ref        => 'true'
    );


    my @nodes_to_check;
    my @live_nodes;
    my $temp_hash   = {};
    my $user        = $args{'user'};

    if ( $args{'node'} ) {
        @nodes_to_check = $args{'node'};
        app->log->debug("Using specified node");
    }
    else {
        @nodes_to_check = ( sort keys %{$network->{'nodes'}} );
        app->log->debug("Using nodes from DB");
    }

    app->log->debug("Query: \[@nodes_to_check\]");

    foreach my $this_node (@nodes_to_check) {

        $network->{'nodes'}{$this_node}{'status'} = 'offline';
        app->log->debug("Query $this_node for games...");

        my $ip = $network->{'nodes'}{$this_node}{'ip'};

        my $ssh = connectSSH( user => $user, ip => $ip, ssh_master => $args{'ssh_master'} );
        if ( not $ssh->{'link'} or $ssh->{'error'}) {
            app->log->warn("Query $this_node for games: LINK FAILED $ssh->{'error'}");
            next;
        }

        $network->{'nodes'}{$this_node}{'status'} = 'online';
        $network->{'nodes'}{$this_node}{'ip'}     = $ip;

        #my @cmd = "ps axo user:20,pid,ppid,pcpu,pmem,vsz,rss,cmd | grep -i ' [s]creen.*server\\|[j]ava.*server'";
        my @cmd = q( ps --no-headers axo user:20,pid,ppid,pcpu,pmem,vsz,rss,cmd );
        my $screen_list = $ssh->{'link'}->capture(@cmd);

        my @screen_list = split( '\n', $screen_list );

        # Extract and colate key information - index on node and pip
        foreach my $this_game (@screen_list) {
            my @column = split( / +/, $this_game );

                if ( $this_game =~ /SCREEN.*server/ or $this_game =~ /java.*server/ ) {

                if ( $column[2] eq '1' ) {
                    # SCREEN has ppid of 1. Load the PID and game
                    $temp_hash->{ $column[1] . $this_node }{'node'} = $this_node;
                    $temp_hash->{ $column[1] . $this_node }{'ip'}   = $ip;
                    $temp_hash->{ $column[1] . $this_node }{'user'} = $column[0];
                    $temp_hash->{ $column[1] . $this_node }{'game'} = $column[12];
                }

                if ( $column[2] ne '1' ) {
                    # Match java child ppid to SCREEN pid to reference correct hash
                    $temp_hash->{ $column[2] . $this_node }{'pid'}  = $column[1];
                    $temp_hash->{ $column[2] . $this_node }{'ppid'} = $column[2];
                    $temp_hash->{ $column[2] . $this_node }{'pcpu'} = $column[3];
                    $temp_hash->{ $column[2] . $this_node }{'pmem'} = $column[4];
                    $temp_hash->{ $column[2] . $this_node }{'vsz'}  = $column[5];
                    $temp_hash->{ $column[2] . $this_node }{'rss'}  = $column[6];
                }
            }
            $network->{'nodes'}{$this_node}{'rss'}     += $column[6];
            $network->{'nodes'}{$this_node}{'pcpu'}    += $column[3];

        }
    }

    ## Remap temp_hash into return_hash based on $list_by arg
    #  Using list_by|game pair to avoind duplicates
    foreach my $result ( keys %$temp_hash ) {
        my $list_by = $temp_hash->{$result}{ $args{'list_by'} };

        my $game = $temp_hash->{$result}{'game'};

        app->log->warn("[!!] $game is running multiple times!")
          if ( $network->{'games'}{$game}{'pid'} );

        $network->{'games'}{$game}{'node'} = $temp_hash->{$result}{'node'};
        $network->{'games'}{$game}{'user'} = $temp_hash->{$result}{'user'};
        $network->{'games'}{$game}{'game'} = $temp_hash->{$result}{'game'};
        $network->{'games'}{$game}{'pid'}  = $temp_hash->{$result}{'pid'};
        $network->{'games'}{$game}{'ppid'} = $temp_hash->{$result}{'ppid'};
        $network->{'games'}{$game}{'pcpu'} = $temp_hash->{$result}{'pcpu'};
        $network->{'games'}{$game}{'pmem'} = $temp_hash->{$result}{'pmem'};
        $network->{'games'}{$game}{'vsz'}  = $temp_hash->{$result}{'vsz'};
        $network->{'games'}{$game}{'rss'}  = $temp_hash->{$result}{'rss'};
        $network->{'games'}{$game}{'ip'}   = $temp_hash->{$result}{'ip'};
    }

    if ( $args{'game'} ) {
        return $network->{'games'}{$args{'game'}}{'node'} if ( $network->{'games'}{$args{'game'}}{'pid'} )
    }
    else {
        return $network;
    }
}

sub registerGame {

    my %args = (
        game => '',
        @_,
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
        @_,
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


sub getFiles {
    my %args = (
        user => '',
        ip   => '',
        game => '',
        @_,
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
        @_,
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
        @_,
    );

    my $game = $args{'game'};
    my $node = $args{'node'};

    app->log->info("Halting: $game");

    sendCommand( command => "stop^Mend", game => $game, node => $node, ssh_master => $args{'ssh_master'} );

    sleep(20);

    unless ( checkIsOnline( list_by => 'node', node => '', game => $game, ssh_master => $args{'ssh_master'} ) ) {
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
        @_,
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

    app->log->info("storing: $game");

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
        @_,
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
       $boot_strap  = qq( mkdir -p $path/logs && cd $path  && );
       $boot_strap .= qq( echo "eula=true" > eula.txt && );
       $boot_strap .= qq( touch logs/gc.log && );
       $boot_strap .= qq( [ -f spigot.yml ] && sed -i '/bungeecord:/s/false/true/' spigot.yml && );
       $boot_strap .= qq( [ -f paper.yml  ] && sed -i '/bungee-online-mode:/s/false/true/' paper.yml && );
       $boot_strap .= qq( [ -f server.properties ] && sed -i '/online-mode=/s/true/false' server.properties  );

    $settings->{$game}{'java_flags'} =~ s/^'//;
    $settings->{$game}{'java_flags'} =~ s/'$//;

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

    # Containerize game in screen, append hardcopy on exit to catch final words
    $ssh->{'link'}->system("$invocation");

    my @cmd = qq(screen -S $game -X colon "logfile flush 5^M");
    $ssh->{'link'}->system(@cmd);

    sleep(10);

    if ( checkIsOnline( list_by => 'game', node => '', game => $game, ssh_master => $args{'ssh_master'} ) ) {
        app->log->info("$game is online");
        return 0;
    }
    else {
        app->log->info("$game boot failed");
        return 1;
    }
}

sub bootStrap {
    my %args = (
        game       => '',
        server_bin => '',
        upgrade    => '',
        @_,
    );

    my $game = $args{'game'};

    return "$game is already online"
      if ( checkIsOnline( list_by => 'game', node => '', game => $game, ssh_master => $args{'ssh_master'} ) );

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

    app->log->info("bootstrap $game begin");

    my $user = $settings->{$game}{'node_usr'};
    my $ssh  = connectSSH( user => $user, ip => $ip, ssh_master => $args{'ssh_master'} );
    return $ssh->{'error'} if $ssh->{'error'};
    return $ssh->{'debug'} if $ssh->{'debug'};


    my $path = qq($settings->{$game}{'node_path'}/$game/game_files);

    my $boot_strap;
    my $task;
    my $output;

    $task       = qq( bootstrap $game: creating paths );
    $boot_strap = qq( mkdir -p $path/logs ; echo "$? paths");
       $output .= $ssh->{'link'}->capture("$boot_strap");
       app->log->info("$task success $boot_strap");

    $task       = qq( bootstrap $game: eula.txt );
    $boot_strap = qq( cd $path;  echo "eula=true" > eula.txt ; echo "$? eula" );
       $output .= $ssh->{'link'}->capture("$boot_strap");
       app->log->info("$task success $boot_strap");

    $task       = qq( bootstrap $game: log files );
    $boot_strap = qq( touch $path/logs/gc.log ; echo "$? gc.log" );
       $output .= $ssh->{'link'}->capture("$boot_strap");
       app->log->info("$task success $boot_strap");

    $task       = qq( bootstrap $game: spigot.yml );
    $boot_strap = qq( cd $path; [ -f spigot.yml ] && sed -i '/bungeecord:/s/false/true/' spigot.yml ; echo "$? spigot.yml" );
       $output .= $ssh->{'link'}->capture("$boot_strap");
       app->log->info("$task success $boot_strap");

    $task       = qq( bootstrap $game: paper.yml );
    $boot_strap = qq( cd $path; [ -f paper.yml  ] && sed -i '/bungee-online-mode:/s/false/true/' paper.yml ; echo "$? paper.yml" );
       $output .= $ssh->{'link'}->capture("$boot_strap");
       app->log->info("$task success $boot_strap");

    $task        = qq( bootstrap $game: server properties );
    $boot_strap  = qq( cd $path; [ -f server.properties ] && );
    $boot_strap .= qq(sed -i '/online-mode=/s/true/false/' server.properties ; echo "$? server.properties" );
       $output  .= $ssh->{'link'}->capture("$boot_strap");
       app->log->info("$task success $boot_strap");

    $task       = "bootstrap environment prepared";
       app->log->info("$task");
       $output .= $task;

       return $output;
}


sub deployGame {
    my %args = (
        game => '',
        @_,
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

    my $rsync_cmd  = qq(rsync -auv --delete --exclude="game_files/log/*" -e 'ssh -o StrictHostKeyChecking=no );
       $rsync_cmd .= qq(-o PasswordAuthentication=no -o BatchMode=yes' $cp_from $cp_to);
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
        @_,
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
    my $java_cmd  = 'find /lib/ /opt/ 2>&1 /dev/null | grep bin/java$';

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

        $output{'0_neo'}   = $ssh->{'link'}->capture(@neo_cmd);
        $output{'1_java'}  = $ssh->{'link'}->capture($java_cmd);

        $output{'2_inet'}  = $ssh->{'link'}->capture($con_cmd);
        $output{'4_net'}   = $ssh->{'link'}->capture($net_cmd) . $iperf;

        $output{'5_cpu'}   = $ssh->{'link'}->capture(@cpu_cmd);
        $output{'6_mem'}   = $ssh->{'link'}->capture(@mem_cmd);
        $output{'7_proc'}  = $ssh->{'link'}->capture(@pid_cmd);

        $output{'8_io'}    = $ssh->{'link'}->capture($io_cmd);
        $output{'9_disk'}  = $ssh->{'link'}->capture($df_cmd);

    return \%output;
}

app->start;

__DATA__


@@ layouts/template.html.ep
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/css/bootstrap.min.css"
        rel="stylesheet"
        integrity="sha384-iYQeCzEYFbKjA/T2uDLTpkwGzCiq6soy8tYaI1GyVh/UjpbCx/TYkiZhlZB6+fzT"
        crossorigin="anonymous">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.9.1/font/bootstrap-icons.css">
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.1/jquery.min.js"></script>


<style>

body {
  background-image: url("/images/background.jpg");
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
    min-width: 40%;
}

.data a, .data span, .data tr, .data td { white-space: pre; }

#command-content{
    text-indent: -0.5em;
    padding-left: 1em; font-size: small; color: #41FF00;
    height: 70vh;
    overflow: auto;
    display: flex;
    flex-direction: column-reverse;
    background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
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


<nav class="navbar navbar-expand-lg static-top sticky-top navbar-dark bg-dark ">
  <div class="container-fluid">
        <a class="navbar-brand" href="/">
          <img src="/images/logo.png" alt="" height="50">
          <small><%= $username %></small>
       </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarTogglerDemo01"
                aria-controls="navbarTogglerDemo01" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
      </button>

  <div class="collapse navbar-collapse " id="navbarTogglerDemo01">

      <ul class="navbar-nav nav-tabs">

      % if ( $username ) {
        <li class="nav-item">
          <a class="nav-link" role="button" aria-current="page" href="/">network</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" role="button" aria-current="page" href="/pool"><%= $pool %></a>
        </li>
        <li class="nav-item">
          <a class="nav-link" role="button" href="/status">status</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" role="button" target="_blank"
          href="https://github.com/splatage/deploy/wiki">help</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" role="button" href="/yancy/auth/password/logout">logout</a>
        </li>

        <!-- superuser menu to edit settings -->
        <!-- admin user menus to minion, mojolicious logfile and reload  -->
        % if ( $is_admin ) {
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
            admin
          </a>
          <ul class="dropdown-menu text-light bg-dark">
            <li><a class="dropdown-item text-muted" href="/minion">minions</a></li>
            <li><a class="dropdown-item text-muted" href="/logfile">logfile</a></li>
            <li><a class="dropdown-item text-muted" href="/reload">reload</a></li>
            % if ( $c->yancy->auth->current_user->{'super_user'} ) {
            <li><hr class="dropdown-divider"></li>
            <li><a class="dropdown-item text-muted" href="/yancy">superuser</a></li>
            % }
          </ul>
        </li>
        % }
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
</body>
</html>

<link rel="stylesheet" href="https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/themes/smoothness/jquery-ui.css">
<script src="https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/jquery-ui.min.js"></script>

<script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"
    integrity="sha384-oBqDVmMz9ATKxIep9tiCxS/Z9fNfEXiDAYTujMAeBAsjFuCZSmKbSSUnQlmh/jp3"
    crossorigin="anonymous"></script>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.1/dist/js/bootstrap.min.js"
    integrity="sha384-7VPbUDkoPSGFnVtYi0QogXtr74QeVeeIs99Qfg5YCF+TidwNdjvaKZX19NZ/e6oz"
    crossorigin="anonymous"></script>


<script type="text/javascript">
$(document).ready(function() {
    $('.spinner-hide').hide();
    window.setTimeout(function() {
        $(".alert-fadeout").fadeTo(1000, 0).slideUp(1000, function() {
            $(this).remove();
        });
    }, 5000);
});
</script>


@@ pool.html.ep
% layout 'template';

<div class="container-fluid text-left">
  <div class="alert alert-success alert-dismissible fade show" role="alert">
    <h4 class="alert-heading">my games: <%= $pool %> pool </h4>
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
  </div>
  % for my $game (sort keys %{$network->{'games'}} ) {
  %# my $pool
  %= next unless ( $network->{'games'}{$game}{'pool'} eq $pool );
  <div class="row height: 40px">
    <div class="col d-flex justify-content-start mb-2 shadow">
      <div class="media">
        <a href="/filemanager/<%= $game %>" class="list-group-item-action list-group-item-light">
          <img class="zoom align-self-top mr-3" src="/images/mc_folders.png" alt="Generic placeholder image" height="35">
          </image>
        </a>
        <a href="/log/<%= $network->{'games'}{$game}{node} %>/<%= $game %>" class="list-group-item-action list-group-item-light">
          <img class="zoom align-self-top mr-3" src="/images/matrix_log.png" alt="Generic placeholder image" height="35">
          </image>
        </a>
        <img class="zoom align-self-top mr-3" src="/images/creeper-server-icon.png" alt="Generic placeholder image" height="25">
        </h4><%= $game %> </h4>
        </image>
      </div>
    </div>
    % if ( ! app->minion->lock($game, 0) or $locks->{$game} eq 'true' ) {
    <div class="col d-flex justify-content-end mb-2 shadow">
      <a class="ml-1 btn btn-sm btn-outline-danger
               justify-end" href="/minion/locks" role="button">task is running</a>
    </div>
  </div>
  % next; }
  % if ( defined $network->{'games'}{$game}{'pid'} ) {
  <div class="col d-flex justify-content-end mb-2 shadow">
    <a class="ml-1 btn btn-sm btn-outline-secondary  custom
              justify-end" data-toggle="tooltip" data-placement="top" title="snapshot game to storage"
              href="/store/<%= $game %>/<%= $game %>" role="button">store</a>
    <a class="ml-1 btn btn-sm btn-outline-info custom
              justify-end" data-toggle="tooltip" data-placement="top" title="connect into the network"
              href="/link/<%= $game %>/<%= $game %>" role="button">link</a>
    <a class="ml-1 btn btn-sm btn-outline-info custom
              justify-end" data-toggle="tooltip" data-placement="top" title="remove connection from the network"
              href="/drop/<%= $game %>/<%= $game %>" role="button">drop</a>
    <a class="ml-1 btn btn-sm btn-danger     custom
              justify-end" data-toggle="tooltip" data-placement="top" title="shutdown and copy to storage"
              href="/halt/<%= $game %>/<%= $game %>" role="button">halt</a>
  </div>
  % } else {
  <div class="col d-flex justify-content-end mb-2 shadow">
    <a class="ml-1 btn btn-sm btn-outline-secondary  custom
              justify-end" data-toggle="tooltip" data-placement="top" title="copy game data from storage to node"
              href="/deploy/<%= $game %>/<%= $game %>" role="button">deploy</a>
    <a class="ml-1 btn btn-sm btn-outline-info     custom
              justify-end" data-toggle="tooltip" data-placement="top" title="remove connection from the network"
              href="/drop/<%= $game %>/<%= $game %>" role="button">drop</a>
    <a class="ml-1 btn btn-sm btn-success    custom
              justify-end" data-toggle="tooltip" data-placement="top" title="copy from storage and start"
              href="/boot/<%= $game %>/<%= $game %>" role="button">boot</a>
  </div>
  % }
</div>
% }

<script>
document.addEventListener("DOMContentLoaded", function(event) {
    var scrollpos = sessionStorage.getItem('scrollpos');
    if (scrollpos) {
        window.scrollTo(0, scrollpos);
        sessionStorage.removeItem('scrollpos');
    }
});

window.addEventListener("beforeunload", function(e) {
    sessionStorage.setItem('scrollpos', window.scrollY);
});
</script>


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
       % #for my $node ( sort keys %{$network->{nodes} ) {
          % #if ( $network->{nodes}{$node}{'status'} eq 'online' ) {
           <div class="media mt-2">
              <a href="/info/<%= $node %>" class="list-group-item-action list-group-item-light">
                <img class="align-self-top mr-1 mt-2 mb-2" src="/images/application-server-.png"
                  alt="Generic placeholder image" height="80">
                </img>
                <h3>
                    <%= $node %>
                </h3>
              </a>
            </div>
        <div class="row height: 40px">
        <hr>
        <h5 class="text-success">games</h5>
        </div>
            % for my $game ( sort keys %{$network->{'games'}} ) {
            % next unless ( $network->{'games'}{$game}{'node'} eq $node );
      <div class="row height: 40px">
        <div class="col d-flex justify-content-start mb-2 shadow">
          <div class="media" >
            <a href="/filemanager/<%= $game %>" class="list-group-item-action list-group-item-light">
              <img class="zoom align-self-top mr-3" src="/images/mc_folders.png"
                alt="Generic placeholder image" height="35">
              </image>
            </a>
            <a href="/log/<%= $network->{'games'}{$game}{node} %>/<%= $game %>" class="list-group-item-action list-group-item-light">
              <img class="zoom align-self-top mr-3" src="/images/matrix_log.png"
                alt="Generic placeholder image" height="35">
              </image>
            </a>
            <img class="zoom align-self-top mr-3" src="/images/creeper-server-icon.png"
              alt="Generic placeholder image" height="25">
              </h4> <%= $game %> </h4>
            </image>
          </div>
        </div>
        % if ( ! app->minion->lock($game, 0) or defined $locks->{$game} ) {
          <div class="col d-flex justify-content-end mb-2 shadow">
            <a class="ml-1 btn btn-sm btn-outline-danger
               justify-end" href="/minion/locks"      role="button">task is running</a>
          </div>
          </div>
        % next; }
        % if ( defined $network->{'games'}{$game}{'pid'} ) {
          <div class="col d-flex justify-content-end mb-2 shadow">
            <a class="ml-1 btn btn-sm btn-outline-secondary  custom
              justify-end" data-toggle="tooltip" data-placement="top" title="snapshot game to storage"
              href="/store/<%= $game %>/<%= $game %>"     role="button">store</a>
            <a class="ml-1 btn btn-sm btn-outline-info custom
              justify-end" data-toggle="tooltip" data-placement="top" title="connect into the network"
              href="/link/<%= $game %>/<%= $game %>"      role="button">link</a>
            <a class="ml-1 btn btn-sm btn-outline-info custom
              justify-end" data-toggle="tooltip" data-placement="top" title="remove connection from the network"
              href="/drop/<%= $game %>/<%= $game %>"      role="button">drop</a>
            <a class="ml-1 btn btn-sm btn-danger     custom
              justify-end" data-toggle="tooltip" data-placement="top" title="shutdown and copy to storage"
              href="/halt/<%= $game %>/<%= $game %>"      role="button">halt</a>
          </div>
        % } else {
          <div class="col d-flex justify-content-end mb-2 shadow">
            <a class="ml-1 btn btn-sm btn-outline-secondary  custom
              justify-end" data-toggle="tooltip" data-placement="top" title="copy game data from storage to node"
              href="/deploy/<%= $game %>/<%= $game %>"    role="button">deploy</a>
            <a class="ml-1 btn btn-sm btn-outline-info     custom
              justify-end" data-toggle="tooltip" data-placement="top" title="remove connection from the network"
              href="/drop/<%= $game %>/<%= $game %>"      role="button">drop</a>
            <a class="ml-1 btn btn-sm btn-success    custom
              justify-end" data-toggle="tooltip" data-placement="top" title="copy from storage and start"
              href="/boot/<%= $game %>/<%= $game %>"      role="button">boot</a>
          </div>
      % }
      </div>
    % }
  </div>

<script>
document.addEventListener("DOMContentLoaded", function(event) {
    var scrollpos = sessionStorage.getItem('scrollpos');
    if (scrollpos) {
        window.scrollTo(0, scrollpos);
        sessionStorage.removeItem('scrollpos');
    }
});

window.addEventListener("beforeunload", function(e) {
    sessionStorage.setItem('scrollpos', window.scrollY);
});
</script>


@@ index.html.ep
% layout 'template';

<div class="alert alert-success alert-dismissible fade show" role="alert">
  <h4 class="alert-heading"><%= $title %> </h4>
  <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
</div>
<body class="m-0 border-0">
  <div class="container-fluid text-left">
    <div class="row justify-content-start">
    % for my $node ( sort keys %{$network->{'nodes'}} ) {
        % if ( $network->{'nodes'}{$node}{'status'} eq 'online' ) {
        <div class="col-12 col-md-3 shadow bg-medium mt-4 mb-2 rounded">
        <div class="media mt-2 mb-2">
          <img class="align-self-top mr-1 mt-2 mb-2" src="/images/application-server-.png" alt="Generic placeholder image" height="80">
          <a href="/node/<%= $node %>" class="position-absolute bottom-10 end-10 translate-middle badge bg-dark fs-6">
          <%= $node %> </a><%= int($network->{'nodes'}{$node}{'pcpu'} + 0.5) %>% |
          <%= int($network->{'nodes'}{$node}{'rss'}/1024 + 0.5) %>M </img>
          <!--  games list  -->
          <div class="bg-success text-dark bg-opacity-10 list-group list-group-flush">
          % for my $game ( sort keys %{$network->{'games'}} ) {
            % next unless ( $network->{'games'}{$game}{'node'} eq $node );
            % if ( defined $network->{'games'}{$game}{'pcpu'} ) {
            <a href="/log/<%= $network->{'games'}{$game}{'node'} %>/<%= $game %>"
               class="fs-5 list-group-item-action list-group-item-success mb-1">
              <span class="badge badge-primary text-dark"><%= $game %> </span>
              <span style="float:right; mr-1" class="mr-1 fs-6">
                <small><%= int($network->{'games'}{$game}{'pcpu'} + 0.5) %> % |
                  <%= int($network->{'games'}{$game}{'rss'}/1024 + 0.5) %>M </small>
                % } else {
                <a href="/log/<%= $node %>/<%= $game %>" class="fs-5 list-group-item-action list-group-item-danger mb-1">
                  <span class="badge badge-primary text-dark"><%= $game %> </span>
                  <span style="float:right; mr-1" class="mr-1">
                    <img src="/images/redX.png" alt="X" image" height="25">
                % }
                  </span>
                </a>
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
        % for my $node (sort keys %{$network->{'nodes'}} ) {
          % if ( $network->{'nodes'}{$node}{'status'} eq 'offline' ) {
          <div class="col-12 col-md-3 shadow bg-medium mt-4 rounded">
            <div class="media mt-2">
              <img class="align-self-top mr-1 mt-2 mb-2" src="/images/application-server-.png" alt="Generic placeholder image" height="80">
              <a href="#" class="position-absolute bottom-10 end-10 translate-middle badge bg-dark fs-6"><%= $node %> </a>
              </img>
              <div class="bg-success text-dark bg-opacity-10 list-group list-group-flush">
                %for my $game ( sort keys %{$network->{'games'}} ) {
                % if ( $network->{'games'}{$game}{'node'} eq $node ) {
                <a href="#" class="fs-5 list-group-item-action list-group-item-danger mb-1">
                  <span class="badge badge-primary text-dark"><%= $game %> </span>
                  <span style="float:right; mr-1" class="mr-1">
                    <img src="/images/redX.png" alt="X" image" height="25">
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


@@ node_details.html.ep
% layout 'template';

<div class="container-fluid text-left">
  <div class="alert alert-success" role="alert">
    <h4 class="alert-heading"> debug info for <%= $node %> </h4>
  </div>
  <div class="accordion accordion-flush" id="accordionFlushExample">
    % my %numbers = (1 => 'One', 2 =>'Two', 3 => 'Three', 4 => 'Four', 5 => 'Five', 6 => 'Six', 7 => 'Seven', 8 => 'Eight', 9 => 'Nine');
    % my $count;
    % my %results = %$results;
    % my $show = 'show';
    % foreach my $title (sort keys %results) {
        % my $info = $results{$title};
        % my @lines = split(/\n/, $info);
        % $count++;
        % $show = undef unless ($count eq 1);
  <div class="accordion-item">
      <h2 class="accordion-header" id="flush-heading<%= $numbers{$count} %>">
        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#flush-collapse<%= $numbers{$count} %>" aria-expanded="false" aria-controls="flush-collapse<%= $numbers{$count} %>">
          <strong><%= $title %> </strong>
          <hr>
        </button>
      </h2>
      <div id="flush-collapse<%= $numbers{$count} %>" class="accordion-collapse collapse <%= $show %>" aria-labelledby="flush-heading<%= $numbers{$count} %>" data-bs-parent="#accordionFlushExample">
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


@@ login.html.ep
% layout 'template';

<body class="m-0 border-0 mt-5" style="background-size: cover; background-image: url('https://cdn.mos.cms.futurecdn.net/52K7sgnQLSJ8ggfyfvz9yB-970-80.jpg.webp');">
  <div class="container-fluid text-left bg-opacity-10" style="--bs-bg-opacity: .10;">
  %= $c->yancy->auth->login_form
  </div>
</body>


@@ logfile.html.ep
% layout 'template';

<div class="container-fluid text-left">
  <div class="alert alert-success alert-dismissible fade show" role="alert">
    <h4 class="alert-heading">server logfile</h4>
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
  </div>
</div>
<div id='command-content' class="text-wrap container-sm text-break"> </div>
<!-- /serverlog/:task   -->
<div class="d-grid gap-2 d-md-block">
  <a class="btn btn-outline-warning" href="/serverlog/clear" role="button">clear</a>
  <a class="btn btn-outline-success" href="/serverlog/info" role="button">info</a>
  <a class="btn btn-outline-success" href="/serverlog/debug" role="button">debug</a>
  <a class="btn btn-outline-success" href="/serverlog/trace" role="button">trace</a>
</div>

<script type="text/javascript">
var socket;
var ws_host;

$(document).ready(function() {
    connect();

    function connect() {
        ws_host = window.location.href;
        ws_host = ws_host.replace(/http:/, "ws:");
        ws_host = ws_host.replace(/https:/, "wss:");
        ws_host = ws_host + "-ws";
        socket = new WebSocket(ws_host);

        socket.onclose = function(e) {
            console.log('Socket is closed. Reconnect will be attempted in 1 second.', e.reason);
            setTimeout(function() {
                connect();
            }, 1000);
        };

        socket.onmessage = function(msg) {
            $('#command-content').prepend(msg.data);
        };
    };

    function send(e) {
        if (e.keyCode !== 13) {
            return false;
        }
        var cmd = document.getElementById('cmd').value;
        document.getElementById('cmd').value = '';
        console.log('send', cmd);
        socket.send(JSON.stringify({
            cmd: cmd
        }));
    };

    document.getElementById('cmd').addEventListener('keypress', send);
    document.getElementById('cmd').focus();
});
</script>


@@ gamelog.html.ep
% layout 'template';

<div class="container-fluid text-left">
  <div class="alert alert-success alert-dismissible fade show" role="alert">
    <h4 class="alert-heading">command console: <%= $game %> on <%= $node %> </h4>
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
  </div>
  <div id='command-content' class="text-wrap container-sm text-break"> </div>
</div>
<div class="input-group input-group-sm mb-3">
  <button class="btn btn-primary" type="button" data-bs-toggle="offcanvas" data-bs-target="#offcanvasExample" aria-controls="offcanvasExample"> Options </button>
  <!-- Side Panel -->
  <div class="offcanvas offcanvas-start text-bg-dark" tabindex="-1" id="offcanvasExample" aria-labelledby="offcanvasExampleLabel">
    <div class="offcanvas-header">
      <h5 class="offcanvas-title" id="offcanvasExampleLabel">Control Options</h5>
      <button type="button" class="btn-close" data-bs-dismiss="offcanvas" aria-label="Close"></button>
    </div>
    <div class="offcanvas-body">
    % if (app->minion->lock($game, 0)) {
    <h6 class="mt-3">storage</h6>
      <hr>
      <div class="list-group">
        <a href="/store/<%= $game %>/<%= $node %>" class="list-group-item list-group-item-action list-group-item-secondary">store </a>
        <a href="/deploy/<%= $game %>/<%= $node %>" class="list-group-item list-group-item-action list-group-item-secondary">deploy </a>
      </div>
      <h6 class="mt-3">network</h6>
      <hr>
      <div class="list-group">
        <a href="/drop/<%= $game %>/<%= $node %>" class="list-group-item list-group-item-action list-group-item-secondary">drop </a>
        <a href="/deploy/<%= $game %>/<%= $node %>" class="list-group-item list-group-item-action list-group-item-secondary">link </a>
      </div>
      <h6 class="mt-3">power</h6>
      <hr>
      <div class="list-group">
        <a href="/halt/<%= $game %>/<%= $node %>" class="list-group-item list-group-item-action list-group-item-dark">halt </a>
        <a href="/boot/<%= $game %>/<%= $node %>" class="list-group-item list-group-item-action list-group-item-dark">boot </a>
      </div>
      <h6 class="mt-3">admin</h6>
      <hr>
      <div class="list-group">
        <a href="/bootstrap/<%= $game %>/<%= $node %>" class="list-group-item list-group-item-action list-group-item-dark">bootstrap </a>
      </div>
      % } else {
      <div class="col d-flex justify-content-end mb-2 shadow">
        <a class="ml-1 btn btn-sm btn-outline-danger
                        justify-end" href="/minion/locks" role="button">task is running</a>
      </div>
      % }
    </div>
  </div>
  <!-- Console Form -->
  <span class="input-group-text" id="inputGroup-sizing-sm">
    <b><%= $game %>@<%= $node %> :~ </small>
    </b>
  </span>
  <input type="text" autocomplete="off" class="form-control" id="cmd" placeholder="console" aria-label="Sizing example input" aria-describedby="inputGroup-sizing-sm">
</div>

<script type="text/javascript">
var socket;
var ws_host;

$(document).ready(function() {
    connect();

    function connect() {
        ws_host = window.location.href;
        ws_host = ws_host.replace(/http:/, "ws:");
        ws_host = ws_host.replace(/https:/, "wss:");
        ws_host = ws_host + "-ws";
        socket = new WebSocket(ws_host);

        socket.onclose = function(e) {
            console.log('Socket is closed. Reconnect will be attempted in 1 second.', e.reason);
            setTimeout(function() {
                connect();
            }, 1000);
        };

        socket.onmessage = function(msg) {
            $('#command-content').prepend(msg.data);
        };
    };

    function send(e) {
        if (e.keyCode !== 13) {
            return false;
        }
        var cmd = document.getElementById('cmd').value;
        document.getElementById('cmd').value = '';
        console.log('send', cmd);
        socket.send(JSON.stringify({
            cmd: cmd
        }));
    };

    document.getElementById('cmd').addEventListener('keypress', send);
    document.getElementById('cmd').focus();
});
</script>


@@ filemanager.html.ep
% layout 'template';

<head>
<style type="text/css" media="screen">
    #editor {
        position: relative;
        top: 0;
        right: 0;
        bottom: 0;
        left: 0;
        width: 100%;
        height: 65vh;
</style>

</head>
<body>
<div class="container-fluid text-left">
  <div class="alert alert-success alert-dismissible show" role="alert">
    <h4 class="alert-heading">
      <img class="align-self-left mr-3" src="/images/mc_folders.png" alt="Generic placeholder image" height="50">
      </image><%= $game %> staging area manager
    </h4>
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
  </div>
</div>
<!-- filemanager notification -->
<div id='filemanager-notification' class="text-break container-sm text-break"></div>
<!-- filemanager editor -->
<div id='filemanager-editor' class="text-break container-sm text-break"></div>
<!-- filemanager content -->
<div id='filemanager-content' class="text-break container-sm text-break"></div>
                 <!-- Modal -->
                <div class="modal fade" id="editor_m" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1"
                     aria-labelledby="editor_label" aria-hidden="true" >
                 <div class="modal-dialog modal-xl">
                    <div class="modal-content">
                      <div class="modal-header">
                        <h1 class="modal-title fs-5" id="editor_label">file editor</h1>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                      </div>
                      <div class="modal-body">
                        <!-- editor embedded here -->
                        <div id="editor"></div>
                        <!-- -->
                      </div>
                  <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">close</button>
            <button type="button" class="btn btn-primary" onclick="edit_file('save')">save</button>
          </div>
        </div>
      </div>
    </div>
</body>


<script src="/ace-builds-master/src-min-noconflict/ace.js"></script>


<script>
var socket;
var ws_host;

$(document).ready(function() {
    connect();

    function connect() {
        ws_host = window.location.href;
        ws_host = ws_host.replace(/http:/, "ws:");
        ws_host = ws_host.replace(/https:/, "wss:");
        ws_host = ws_host + "-ws";
        socket = new WebSocket(ws_host);

        socket.onclose = function(e) {
            console.log('Socket is closed. Reconnect will be attempted in 5 seconds', e.reason);
            setTimeout(function() {
                connect();
            }, 5000);
        };

        socket.onmessage = function(e) {
            // console.log(e.data);
            var data = JSON.parse(e.data);
            if ('base_dir' in data) {
                $('#filemanager-content').html(data.base_dir);
            };
            if ('filename' in data) {
                const link = document.createElement('a');
                link.download = data.filename;
                link.href = window.location.origin + "/" + data.path + "/" + data.filename;
                console.log(link.href);
                link.click();
            };
            if ( 'editor_content' in data ) {
                console.log(data.editor_content);
                editor.session.setValue(data.editor_content);
            };
        };
    };
});

function browser_path(msg) {
    socket.send(JSON.stringify({
        base_dir: msg
    }));
};

function get_file(msg) {
    console.log(msg);
    socket.send(JSON.stringify({
        get_file: msg
    }));
    // alert("preparing to fetch...\n" + decodeURIComponent(msg));
};

function delete_file(msg) {
    console.log(msg);
    let text = "delete\n" + decodeURIComponent(msg);
    if (confirm(text) == true) {
        socket.send(JSON.stringify({
            delete_file: msg
        }));
    }
};

function upload_file(msg) {
    var encoded = encodeURIComponent(msg);
    console.log(encoded);
    socket.send(JSON.stringify({
        upload_file: msg
    }));
};

var editor;
var current_file;
function edit_file(msg) {
    if ( msg == 'save' ) {
        var content = editor.getValue();
            alert( "saved: " + decodeURIComponent(current_file) );

        socket.send(JSON.stringify({
            save_editor_content: content,
            file_path: current_file
        }));
    } else {
        current_file = msg;
        editor = ace.edit("editor");
        editor.setTheme("/ace-builds-master/css/theme/monokai");
        editor.session.setMode("/ace-builds-master/src-min-noconflict/mode/ymal");
        editor.session.setTabSize(4);
        editor.session.setUseSoftTabs(true);
        editor.setShowPrintMargin(false);
        document.getElementById('editor').style.fontSize='1em';
        _('editor_label').innerHTML = "file editor: " + decodeURIComponent(msg);

        socket.send(JSON.stringify({
            load_editor_content: true,
            file_path: msg
        }));
    }
};


function _(el) {
    return document.getElementById(el);
}

function uploadFile(folder) {
    console.log(folder);
    var arrayLength = _("filelist").files.length;

    for (var i = 0; i < arrayLength; i++) {
        var thisfile = _("filelist").files[i];
        var formdata = new FormData();
        formdata.append("file", thisfile);
        formdata.append("folder", folder);

        var ajax = new XMLHttpRequest();

        ajax.upload.addEventListener("loadstart", function(e) {
            var uniqID = Math.floor((Math.random() * 100000));
            this.progressID = "progress_" + uniqID;
            this.filesizeID = "filesize_" + uniqID;
            this.filename = thisfile.name;
            console.log("inserting progress html for " + this.filename + ": " + this.progressID + " " + this.filesizeID);
            $("#dynamic_progress").prepend('<div><progress id="' + this.progressID + '" value="0" max="100" style="width: 50%;"></progress></div>');
       //     $("#dynamic_progress").prepend('<div><b>' + this.filename + '</b></div><div id="' + this.filesizeID + '"><br></div>');
            $("#dynamic_progress").prepend('<b>' + this.filename + '</b></div><div id="' + this.filesizeID + '"><br></div>');
        }, false);

        ajax.upload.addEventListener("progress", function(e) {
            var percent = (e.loaded / e.total) * 100;
            _(this.progressID).value = Math.round(percent);
            _(this.filesizeID).innerHTML = (formatBytes(e.loaded) + " of " + formatBytes(e.total) + " uploaded");
            if (percent == 100) {
                _(this.filesizeID).innerHTML = "moving to staging area...";
            }
        }, false);

        ajax.upload.addEventListener("load", function(e) {
            _(this.filesizeID).innerHTML = "finished";
        }, false);

        ajax.upload.addEventListener("abort", function(e) {
            console.log(this.filename + " upload aborted");
            _(this.filesizeID).innerHTML = "upload aborted";
        }, false);

        ajax.addEventListener("error", function(e) {
            alert("Error callback");
        }, false);

        ajax.open("POST", "/upload");
        ajax.send(formdata);
    }
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
</script>

