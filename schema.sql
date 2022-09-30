-- MariaDB dump 10.19  Distrib 10.5.15-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: 127.0.0.1    Database: deploy
-- ------------------------------------------------------
-- Server version	10.5.15-MariaDB-0+deb11u1-log


--
-- Table structure for table `games`
--

DROP TABLE IF EXISTS `games`;
CREATE TABLE `games` (
  `name` varchar(100) NOT NULL DEFAULT '',
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `store_usr` varchar(255) NOT NULL DEFAULT 'username to access file storage host - needs sshkey access from deploy_user@deploy_host',
  `store` varchar(255) NOT NULL DEFAULT 'host to store game on, finds matching entry in host table',
  `store_path` varchar(255) NOT NULL DEFAULT '/storagehost/file/path',
  `node_usr` varchar(255) NOT NULL DEFAULT 'username to access node that runs - needs sshkey access from deploy_user@deploy_host and store_user@storage_host',
  `node` varchar(255) NOT NULL DEFAULT 'node to run game on',
  `node_path` varchar(255) NOT NULL DEFAULT '~/ramdrive or ~ or /any/other/location',
  `release` varchar(255) NOT NULL DEFAULT '1.19.2',
  `port` int(5) NOT NULL DEFAULT 25500,
  `mem_min` varchar(11) NOT NULL DEFAULT '3G',
  `mem_max` varchar(11) NOT NULL DEFAULT '3G',
  `java_bin` varchar(255) NOT NULL DEFAULT 'java',
  `java_flags` text NOT NULL DEFAULT '-Djava.net.preferIPv4Stack=true -XX:+UseTransparentHugePages -XX:+AlwaysPreTouch -XX:+UseNUMA -XX:ParallelGCThreads=8 -XX:ConcGCThreads=2 -XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200 -XX:+UnlockExperimentalVMOptions -XX:+DisableExplicitGC -XX:+AlwaysPreTouch -XX:G1NewSizePercent=30 -XX:G1MaxNewSizePercent=40 -XX:G1HeapRegionSize=4M -XX:G1ReservePercent=20 -XX:G1HeapWastePercent=5 -XX:G1MixedGCCountTarget=4 -XX:InitiatingHeapOccupancyPercent=15 -XX:G1MixedGCLiveThresholdPercent=90 -XX:G1RSetUpdatingPauseTimePercent=5 -XX:SurvivorRatio=32 -XX:+PerfDisableSharedMem -XX:MaxTenuringThreshold=1 -Dusing.aikars.flags=https://mcflags.emc.gs -Daikars.new.flags=true -Xlog:gc*:logs/gc.log:time,uptime:filecount=5,filesize=1M',
  `isLobby` tinyint(1) NOT NULL DEFAULT 0,
  `isRestricted` tinyint(1) NOT NULL DEFAULT 0,
  `isBungee` tinyint(1) NOT NULL DEFAULT 0,
  `crontab` varchar(64) DEFAULT NULL,
  `pool` varchar(64) NOT NULL DEFAULT 'default',
  PRIMARY KEY (`name`,`port`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Table structure for table `nodes`
--

DROP TABLE IF EXISTS `nodes`;
CREATE TABLE `nodes` (
  `name` varchar(256) NOT NULL DEFAULT '',
  `ip` varchar(16) NOT NULL DEFAULT '',
  `dns_name` varchar(256) NOT NULL DEFAULT '',
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `isGateway` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`name`,`ip`,`dns_name`),
  UNIQUE KEY `ip` (`ip`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Table structure for table `perms`
--

DROP TABLE IF EXISTS `perms`;
CREATE TABLE `perms` (
  `username` varchar(256) NOT NULL DEFAULT '',
  `pool` varchar(256) NOT NULL DEFAULT '',
  `admin` tinyint(1) NOT NULL DEFAULT 0,
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `email` varchar(256) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `password` varchar(256) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `super_user` tinyint(1) NOT NULL DEFAULT 0,
  `username` varchar(256) NOT NULL DEFAULT '',
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  PRIMARY KEY (`username`,`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- Dump completed on 2022-10-01  9:33:53
