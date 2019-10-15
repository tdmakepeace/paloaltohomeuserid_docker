CREATE DATABASE IF NOT EXISTS PaloAltoHomeUserID /*!40100 DEFAULT CHARACTER SET latin1 */; 
USE PaloAltoHomeUserID; 
CREATE USER  IF NOT EXISTS 'PANuser'@'%' IDENTIFIED BY 'password';
GRANT create, insert, delete, update, select on PaloAltoHomeUserID.* to 'PANuser'@'%' ;
FLUSH privileges;


SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for DHCP
-- ----------------------------
--  DROP TABLE IF EXISTS `DHCP`;
CREATE TABLE  IF NOT EXISTS `DHCP`  (
  `UID` int(11) NOT NULL AUTO_INCREMENT,
  `MacAddr` varchar(20) CHARACTER SET latin1 COLLATE latin1_swedish_ci NOT NULL,
  `Vendor` varchar(50) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  `IPaddr` decimal(11, 0) NULL DEFAULT NULL,
  `Hostname` varchar(50) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  `DisplayName` varchar(50) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  `LeaseTime` datetime(0) NULL DEFAULT NULL,
  `Source` varchar(20) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  PRIMARY KEY (`UID`) USING BTREE,
  UNIQUE INDEX `MacAddr_UNIQUE`(`MacAddr`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 12119 CHARACTER SET = latin1 COLLATE = latin1_swedish_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Table structure for EDL
-- ----------------------------
-- DROP TABLE IF EXISTS `EDL`;
CREATE TABLE  IF NOT EXISTS `EDL`  (
  `UID` int(11) NOT NULL AUTO_INCREMENT,
  `EDLName` varchar(50) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  `Desc` varchar(100) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  PRIMARY KEY (`UID`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 21 CHARACTER SET = latin1 COLLATE = latin1_swedish_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Table structure for EDLData
-- ----------------------------
-- DROP TABLE IF EXISTS `EDLData`;
CREATE TABLE  IF NOT EXISTS `EDLData`  (
  `UID` int(11) NOT NULL AUTO_INCREMENT,
  `EDL_UID` int(11) NULL DEFAULT NULL,
  `EDL_Data` varchar(100) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  PRIMARY KEY (`UID`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 91 CHARACTER SET = latin1 COLLATE = latin1_swedish_ci ROW_FORMAT = Compact;


-- ----------------------------
-- Table structure for GROUPS
-- ----------------------------
-- DROP TABLE IF EXISTS `GROUPS`;
CREATE TABLE  IF NOT EXISTS `GROUPS`  (
  `UID` int(11) NOT NULL AUTO_INCREMENT,
  `GName` varchar(50) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  `Desc` varchar(100) CHARACTER SET latin1 COLLATE latin1_swedish_ci NULL DEFAULT NULL,
  PRIMARY KEY (`UID`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 20 CHARACTER SET = latin1 COLLATE = latin1_swedish_ci ROW_FORMAT = Compact;

-- ----------------------------
-- Table structure for Group_User_Map
-- ----------------------------
-- DROP TABLE IF EXISTS `Group_User_Map`;
CREATE TABLE  IF NOT EXISTS `Group_User_Map`  (
  `UID` int(11) NOT NULL AUTO_INCREMENT,
  `DHCP_UID` int(11) NULL DEFAULT NULL,
  `Group_UID` int(11) NULL DEFAULT NULL,
  PRIMARY KEY (`UID`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 99 CHARACTER SET = latin1 COLLATE = latin1_swedish_ci ROW_FORMAT = Compact;


-- ----------------------------
-- Table structure for AdminAccounts
-- ----------------------------
-- DROP TABLE IF EXISTS `AdminAccounts`;
CREATE TABLE IF NOT EXISTS `AdminAccounts` (
	`id` int(11) NOT NULL AUTO_INCREMENT,
  	`username` varchar(50) NOT NULL,
  	`password` varchar(255) NOT NULL,
  	`email` varchar(100) NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

INSERT INTO `AdminAccounts` (`id`, `username`, `password`, `email`) VALUES (1, 'admin', 'pbkdf2:sha256:50000$8nUothe5$d61eb23f3bcdf602de92b5a86ddb6f6ec398c1cd3231f5ea84968e397995c0d5', 'demo@paloaltonetworks.com');

