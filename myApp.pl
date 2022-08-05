
use v5.28;
use Mojolicious::Lite;
use Mojo::mysql;

plugin 'AutoReload';

# Connect to a local database
#my $mysql = Mojo::mysql->strict_mode('mysql://username@/test');
 
# Connect to a remote database
my $db = Mojo::mysql->strict_mode('mysql://USERNAME:PASSWORD@IP/DB');


# Configure Yancy
plugin Yancy => {
    backend => { mysql => $db },
    # Read the schema configuration from the database
    read_schema => 1,
    schema => {
        game_servers => {
            # Show these columns in the Yancy editor
            'x-list-columns' => [qw( gs_name node_host store_host mem_max server_bin enabled )],
   
        },
    },
};

# Display the gameservers list
get '/', {
    controller => 'yancy',
    action => 'list',
    template => 'index',
    schema => 'game_servers',
    limit => 100,
#        enabled => 1,
#    },
}, 'game_servers.list';

# Set the delivered state of a list row
post '/enabled/:gs_name', {
    controller => 'yancy',
    action => 'set',
    schema => 'game_servers',
    properties => [qw( gs_name node_host enabled )],
    forward_to => 'game_servers.list',
}, 'game_servers.enabled';

# Start the app. Must be the last line of the script.
app->start;

__DATA__
@@ migrations
-- 1 up
##
## Table structure for table `game_servers`
##
DROP TABLE IF EXISTS `game_servers`;
CREATE TABLE `game_servers` (
  `gs_name` varchar(100) NOT NULL,
  `store_usr` varchar(255) NOT NULL DEFAULT 'minecraft',
  `store_host` varchar(255) NOT NULL DEFAULT '192.168.1.200',
  `store_path` varchar(255) NOT NULL DEFAULT '/poolz/archive/MC_STORAGE/current_servers',
  `node_usr` varchar(255) NOT NULL DEFAULT 'minecraft',
  `node_host` varchar(255) NOT NULL DEFAULT '192.168.1.60',
  `node_path` varchar(255) NOT NULL DEFAULT '~',
  `server_bin` varchar(255) NOT NULL DEFAULT 'paper-1.19.1-91.jar',
  `port` int(5) NOT NULL DEFAULT 25500,
  `mem_min` int(11) NOT NULL DEFAULT 3000,
  `mem_max` int(11) NOT NULL DEFAULT 3000,
  `java_bin` varchar(255) NOT NULL DEFAULT '/usr/lib/jvm/java-17-openjdk-amd64/bin/java',
  `java_flags` text NOT NULL DEFAULT '-Djava.net.preferIPv4Stack=true -XX:+UseTransparentHugePages -XX:+AlwaysPreTouch -XX:+UseNUMA -XX:ParallelGCThreads=8 -XX:ConcGCThreads=2 -XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200 -XX:+UnlockExperimentalVMOptions -XX:+DisableExplicitGC -XX:+AlwaysPreTouch -XX:G1NewSizePercent=30 -XX:G1MaxNewSizePercent=40 -XX:G1HeapRegionSize=4M -XX:G1ReservePercent=20 -XX:G1HeapWastePercent=5 -XX:G1MixedGCCountTarget=4 -XX:InitiatingHeapOccupancyPercent=15 -XX:G1MixedGCLiveThresholdPercent=90 -XX:G1RSetUpdatingPauseTimePercent=5 -XX:SurvivorRatio=32 -XX:+PerfDisableSharedMem -XX:MaxTenuringThreshold=1 -Dusing.aikars.flags=https://mcflags.emc.gs -Daikars.new.flags=true -Xlog:gc*:logs/gc.log:time,uptime:filecount=5,filesize=1M',
  `is_lobby` tinyint(1) NOT NULL DEFAULT 0,
  `is_restricted` tinyint(1) NOT NULL DEFAULT 0,
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `mem` int(11) DEFAULT NULL,
  `cpu` int(11) DEFAULT NULL,
  PRIMARY KEY (`gs_name`),
  UNIQUE KEY `gs_name` (`gs_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
##
##
LOCK TABLES `game_servers` WRITE;
UNLOCK TABLES;
##
## Table structure for table `global_settings`
##
DROP TABLE IF EXISTS `global_settings`;
CREATE TABLE `global_settings` (
  `var_name` varchar(100) NOT NULL,
  `var_value` text NOT NULL,
  PRIMARY KEY (`var_name`),
  UNIQUE KEY `var_name` (`var_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
##
##
LOCK TABLES `global_settings` WRITE;
UNLOCK TABLES;
##
## Table structure for table `gs_plugin_settings`
##
DROP TABLE IF EXISTS `gs_plugin_settings`;
CREATE TABLE `gs_plugin_settings` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `gs_name` varchar(100) NOT NULL,
  `cfg_path` varchar(255) NOT NULL,
  `cfg_file` varchar(255) NOT NULL,
  `key` varchar(255) NOT NULL,
  `value` varchar(255) NOT NULL,
  UNIQUE KEY `id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
##
##
LOCK TABLES `gs_plugin_settings` WRITE;
UNLOCK TABLES;
##
## Table structure for table `isOnline`
##
DROP TABLE IF EXISTS `isOnline`;
CREATE TABLE `isOnline` (
  `id` int(9) NOT NULL AUTO_INCREMENT,
  `node` varchar(255) NOT NULL,
  `checked` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' ON UPDATE current_timestamp(),
  `gs_name` varchar(255) NOT NULL,
  `ip` varchar(16) NOT NULL,
  `online` tinyint(1) NOT NULL,
  `mem` int(11) NOT NULL,
  `cpu` int(11) NOT NULL,
  UNIQUE KEY `id` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4;
##
##
LOCK TABLES `isOnline` WRITE;
UNLOCK TABLES;
##
## Table structure for table `logFile`
##
DROP TABLE IF EXISTS `logFile`;
CREATE TABLE `logFile` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `loglevel` varchar(255) DEFAULT NULL,
  `message` text DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=29 DEFAULT CHARSET=utf8mb4;
##
##
LOCK TABLES `logFile` WRITE;
UNLOCK TABLES;
##
## Table structure for table `nodes`
##
DROP TABLE IF EXISTS `nodes`;
CREATE TABLE `nodes` (
  `node_name` varchar(255) NOT NULL,
  `ip` varchar(15) NOT NULL,
  `dns_name` varchar(100) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `is_gateway` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`node_name`),
  UNIQUE KEY `node_name` (`node_name`),
  UNIQUE KEY `ip` (`ip`),
  UNIQUE KEY `dns_name` (`dns_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
##
##
LOCK TABLES `nodes` WRITE;
UNLOCK TABLES;
##
##
##
##




@@ layouts/default.html.ep

<head>
    <script src="/yancy/jquery.js"></script>
    <link rel="stylesheet" href="/yancy/bootstrap.css">
</head>
<body>
    <main class="container">
        %= content
    </main>
</body>

@@ index.html.ep
% layout 'default';


<div style="height: 100px">

   <div class="media" >
       <img class="align-self-center mr-3" 
       src="http://www.splatage.com/wp-content/uploads/2021/06/logo.png" alt="Generic placeholder image" height="75">

       <div class="media-body">
           <h2 class="mt-1">splatage.com Server List</h2>
           <a href="yancy">Server Settings</a>
       </div>
   </div>
</div>



<ul class="list-group ">
   % for my $item ( @$items ) {
       %= csrf_field
       % my $online  = $item->{online};
       % my $is_lobby  = $item->{is_lobby};
       % my $is_restricted  = $item->{is_restricted};

       <li class="list-group-item d-flex justify-content-between list-group-item-action 
            <%= $online ? '' : ' list-group-item-secondary' %>" >
 
            <div class="media" >
                <img class="align-self-top mr-3" 
                    src="http://www.splatage.com/wp-content/uploads/2021/06/creeper-server-icon.png"
                    alt="Generic placeholder image" height="40">

                <div class="btn-group" role="group" aria-label="Basic example">
                    <button type="button" class="
                        <%= $online ? 'btn btn-success btn-sm' : 'btn btn-danger btn-sm' %>
                        ">
                    
                        %= $item->{gs_name}
                    </button>
     
                    <button type="button" class="
                        <%= $online ? 'btn btn-outline-success btn-sm' : 'btn btn-outline-danger btn-sm' %>
                        ">

                        %= $item->{node_host}
                        <%= $online ? 'mem' : '' %>
                        %= $item->{mem}
                        <%= $online ? '' : '' %>
                        <%= $online ? 'cpu' : '' %>
                        %= $item->{cpu}
                        <%= $online ? '%' : '' %>
                    </button>
                    
                </div>
            </div>
            
            %= form_for 'game_servers.enabled', $item, begin
           
            Enabled:
            %= csrf_field
            % my $enabled = $item->{enabled};
            % my $online  = $item->{online};

            <div class="btn-group btn-group-toggle btn-sm">
                <label class="btn btn-xs <%= $enabled ? 'btn-success active  btn-sm' : 'btn-outline-success  btn-sm' %>">
                    <input type="radio" name="enabled" value="true" <%== $enabled ? 'checked' : '' %>> Yes
                </label>

                <label class="btn btn-sm <%= $enabled ? 'btn-outline-danger  btn-sm' : 'btn-danger active  btn-sm' %>">
                    <input type="radio" name="enabled" value="false" <%== $enabled ? '' : 'checked' %>> No
                </label>
            </div>

            <div class="btn-group  btn-sm">
                <label class="btn  btn-sm <%= $online ? 'btn-outline-success  btn-sm' : 'btn-outline-danger  btn-sm' %>">
                    <%== $online ? 'Online' : 'Offline' %>
                </label>
            </div>            
            % end
       </li>
    % }
</ul>

%= javascript begin
    // Automatically submit the form when an input changes
    $( 'form input' ).change( function ( e ) {
        $(this).parents("form").submit();
    } );
% end
