--
-- Table structure for table `games`
--

DROP TABLE IF EXISTS `games`;

CREATE TABLE `games` (
  `name` varchar(100) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `store_usr` varchar(255) NOT NULL DEFAULT 'minecraft',
  `store` varchar(255) NOT NULL DEFAULT 'hostname_to_save_files_on',
  `store_path` varchar(255) NOT NULL DEFAULT '/path/to/saved/games',
  `node_usr` varchar(255) NOT NULL DEFAULT 'minecraft',
  `node` varchar(255) NOT NULL DEFAULT 'hostname to deploy game to',
  `node_path` varchar(255) NOT NULL DEFAULT '~',
  `release` varchar(255) NOT NULL DEFAULT '1.19.2',
  `port` int(5) NOT NULL DEFAULT 25500,
  `mem_min` varchar(11) NOT NULL DEFAULT '3G',
  `mem_max` varchar(11) NOT NULL DEFAULT '3G',
  `java_bin` varchar(255) DEFAULT 'java',
  `java_flags` text NOT NULL DEFAULT '',
  `isLobby` tinyint(1) NOT NULL DEFAULT 0,
  `isRestricted` tinyint(1) NOT NULL DEFAULT 0,
  `isBungee` tinyint(1) NOT NULL DEFAULT 0,
  `crontab` varchar(64) DEFAULT '0 * * * *',
  PRIMARY KEY (`name`),
  UNIQUE KEY `name` (`name`),
  UNIQUE KEY `port` (`port`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `global_settings`
--

DROP TABLE IF EXISTS `global_settings`;

CREATE TABLE `global_settings` (
  `var_name` varchar(100) NOT NULL,
  `var_value` text NOT NULL,
  PRIMARY KEY (`var_name`),
  UNIQUE KEY `var_name` (`var_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `gs_plugin_settings`
--

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

--
-- Table structure for table `isOnline`
--

DROP TABLE IF EXISTS `isOnline`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `isOnline` (
  `node` varchar(255) NOT NULL,
  `checked` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' ON UPDATE current_timestamp(),
  `name` varchar(255) NOT NULL,
  `pid` varchar(128) NOT NULL,
  `ip` varchar(12) NOT NULL,
  `online` tinyint(1) NOT NULL,
  `mem` int(11) NOT NULL,
  `cpu` int(11) NOT NULL,
  `info` text DEFAULT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `logFile`
--

DROP TABLE IF EXISTS `logFile`;

CREATE TABLE `logFile` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `loglevel` varchar(255) DEFAULT NULL,
  `message` text DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `nodes`
--

DROP TABLE IF EXISTS `nodes`;

CREATE TABLE `nodes` (
  `name` varchar(255) NOT NULL,
  `ip` varchar(16) NOT NULL,
  `dns_name` varchar(100) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `isGateway` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`name`),
  UNIQUE KEY `ip` (`ip`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
  `username` varchar(120) DEFAULT NULL,
  `email` varchar(120) NOT NULL,
  `password` varchar(135) DEFAULT NULL,
  `is_admin` tinyint(4) DEFAULT 0,
  PRIMARY KEY (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
