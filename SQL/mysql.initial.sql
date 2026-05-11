CREATE TABLE IF NOT EXISTS `roundcube_2fa` (
  `user_id` int(10) UNSIGNED NOT NULL,
  `secret` varchar(64) DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 0,
  `backup_codes` text DEFAULT NULL,
  PRIMARY KEY (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
