-- phpMyAdmin SQL Dump
-- version 4.0.10deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: May 25, 2016 at 07:20 PM
-- Server version: 10.1.13-MariaDB-1~trusty
-- PHP Version: 5.5.9-1ubuntu4.17

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `threat_actors`
--
CREATE DATABASE IF NOT EXISTS `threat_actors` DEFAULT CHARACTER SET latin1 COLLATE latin1_swedish_ci;
USE `threat_actors`;

-- --------------------------------------------------------

--
-- Table structure for table `password_reset_hashes`
--

CREATE TABLE `password_reset_hashes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `hash` varchar(64) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`,`hash`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(256) NOT NULL,
  `password` varchar(64) NOT NULL,
  `name` varchar(256) NOT NULL,
  `company` varchar(256) DEFAULT NULL,
  `justification` varchar(2048) NOT NULL DEFAULT 'Grandfathered in',
  `email_verified` int(1) NOT NULL DEFAULT '0',
  `verification_hash` varchar(64) NOT NULL,
  `approved` int(1) NOT NULL DEFAULT '0',
  `write_permission` int(1) NOT NULL DEFAULT '0',
  `delete_permission` int(1) NOT NULL DEFAULT '0',
  `admin` int(1) NOT NULL DEFAULT '0',
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `verification_hash` (`verification_hash`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
