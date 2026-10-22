-- =====================================================================
-- MySQL 软阻断系统部署脚本 — 5.5+ 通用版
-- 功能：基于 init_connect + 黑名单表实现 user@ip 粒度的客户端软阻断
-- 核心方案：SELECT CASE WHEN EXISTS(...) THEN EXP(710) ELSE 1 END
--          命中黑名单则 EXP(710) → ERROR 1690 → init_connect 失败 → 连接拒绝
-- 版本：v5.6-final
-- 日期：2026-08-10
-- 兼容：MySQL 5.5.5+ / 5.6 / 5.7 / 8.0 / MariaDB 10.0+ / Percona 5.5+
-- 使用：用 root（SUPER 权限）账号连接 MySQL 后执行本脚本
--   mysql -u root -p < 03-部署脚本-5.5及以上版本.sql
-- =====================================================================
--
-- 版本历史：
--   v3.0  inline REGEXP          -> 引号嵌套问题 X
--   v3.1  inline EXP(710)        -> EXP(710) 可用，但语法混乱
--   v4.0  存储过程+CALL+SIGNAL    -> Bug #47032 修复后 5.7 上 CALL 在 init_connect
--                                    中不可用（正常返回也会导致连接中止）X
--   v5.5  inline IF(... EXP(~0)) -> 使用 IF() 函数语法
--   v5.6  SELECT CASE WHEN       -> 使用标准 CASE WHEN 语法、EXP(710)，更可读 ✓
--
-- 核心原理：
--   init_connect = 'SELECT CASE WHEN EXISTS(
--       SELECT 1 FROM security.client_blacklist
--       WHERE username = SUBSTRING_INDEX(USER(),"@",1)
--         AND client_ip = SUBSTRING_INDEX(USER(),"@",-1)
--         AND status = "active"
--         AND (expire_at IS NULL OR expire_at > NOW())
--   ) THEN EXP(710) ELSE 1 END'
--
--   命中黑名单 → 执行 EXP(710) → ERROR 1690 (DOUBLE value is out of range)
--              → init_connect 失败 → 连接被中止
--              → 客户端收到 ERROR 1184
--   未命中 → 返回 1 → init_connect 成功 → 连接放行
--
-- 为什么用 inline EXP(710) 而不是 CALL + 存储过程：
--   1. Bug #47032 修复后（5.5.21 / 5.6.5 / 5.7+）：CALL 在 init_connect
--      上下文中完全不可用 —— 实测即使存储过程正常返回（无错误），连接也会中止
--   2. inline SQL 不经过 CALL 层，SELECT CASE WHEN 是标准 SQL 语法
--   3. EXP 溢出报错从 5.5.5 开始可用，5.6 / 5.7 / 8.0 全系列无回归风险
--   4. 完全不需要存储过程参与阻断检查
--
-- 为什么用 EXP(710) 而不是 EXP(~0)：
--   EXP(710)：e^710 刚好超过 DOUBLE 上限，是 MySQL 社区公认的溢出触发值
--   EXP(~0) ：~0=18446744073709551615，虽然也能溢出但语义不直观
--   二者触发相同的 ERROR 1690，EXP(710) 可读性和可维护性更好
--
-- 权限权衡（相比 5.1 方案）：
--   - 5.1 方案：DEFINER 隔离，用户只需 EXECUTE ON PROCEDURE
--   - 5.5+ 方案：inline SQL 以用户身份执行，用户需 SELECT ON client_blacklist
--   如果对权限隔离有强需求，请用 VIEW 包装黑名单查询
--
-- 注意：
--   1. init_connect 字符串中引号转义规则：
--      外层用单引号 → 内部单引号用 '' (两个单引号) 转义
--      外层用双引号 → 内部双引号用 "" 转义（推荐，可读性更好）
--   2. mysql CLI 中 SET GLOBAL 建议用双引号包裹字符串值
--   3. my.cnf 持久化时推荐使用双引号版本（避免转义混淆）
--   4. SUPER 权限用户跳过 init_connect，确保 DBA 不会被锁
-- =====================================================================


-- =====================================================================
-- 第一部分：环境检查
-- =====================================================================

SELECT CONCAT('MySQL 版本: ', VERSION()) AS env_check;
-- 需要 5.5.5+（EXP 溢出报错于 5.5.5 引入，5.6/5.7/8.0 全系可用）
-- 如果版本 < 5.5.5，请使用 5.1 部署脚本（block_trigger 方案）

SELECT CONCAT('当前 init_connect: ',
    IFNULL(@@global.init_connect, '(空)')) AS env_check;

SELECT user, host, Super_priv
FROM mysql.user
WHERE Super_priv = 'Y';


-- =====================================================================
-- 第二部分：创建数据库和表
-- =====================================================================

CREATE DATABASE IF NOT EXISTS security
    DEFAULT CHARACTER SET utf8mb4
    COLLATE utf8mb4_general_ci;
USE security;

-- 黑名单主表（与 5.1 方案完全一致）
CREATE TABLE IF NOT EXISTS client_blacklist (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(64)  NOT NULL COMMENT 'MySQL 用户名（不含@host部分）',
    client_ip   VARCHAR(45)  NOT NULL COMMENT '客户端 IP 地址',
    client_port INT UNSIGNED NULL     COMMENT '客户端源端口（可选，仅记录用，匹配不依赖此字段）',
    reason      VARCHAR(500) NOT NULL COMMENT '封禁原因',
    operator    VARCHAR(64)  NOT NULL COMMENT '操作人 DBA 账号名',
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '封禁时间',
    expire_at   TIMESTAMP    NULL DEFAULT NULL COMMENT '过期时间 NULL=永久封禁',
    status      ENUM('active','released') NOT NULL DEFAULT 'active' COMMENT '黑名单状态',
    UNIQUE KEY uk_user_ip_port (username, client_ip, client_port),
    KEY idx_status_expire (status, expire_at),
    KEY idx_ip (client_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='MySQL 客户端软阻断黑名单表';

-- 操作审计日志表（与 5.1 方案完全一致）
CREATE TABLE IF NOT EXISTS block_audit_log (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    action        ENUM('block','unblock','kill','auto_release') NOT NULL COMMENT '操作类型',
    username      VARCHAR(64)  NULL COMMENT '涉及的用户名',
    client_ip     VARCHAR(45)  NULL COMMENT '客户端 IP',
    client_port   INT UNSIGNED NULL COMMENT '客户端源端口',
    connection_id INT UNSIGNED NULL COMMENT '被 KILL 的连接 ID',
    reason        VARCHAR(500) NULL COMMENT '操作原因',
    operator      VARCHAR(64)  NOT NULL COMMENT '操作人',
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '操作时间'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='软阻断操作审计日志';


-- =====================================================================
-- 第三部分：创建管理存储过程
-- =====================================================================
-- 说明：
--   阻断检查由 init_connect 中的 inline SQL 完成，不依赖存储过程
--   以下存储过程仅供 DBA 进行封禁/解封/查看/日志等管理操作
-- =====================================================================

USE security;
DELIMITER //

-- ---------------------------------------------------------------------
-- 存储过程：sp_block_client
-- 功能：一键封禁客户端（写黑名单 + KILL 现有连接 + 记录审计日志）
-- 调用示例：
--   CALL security.sp_block_client('app_user','10.0.0.5',54321,'非法DROP TABLE','dba_zhang',NULL);
--   CALL security.sp_block_client('app_user','10.0.0.5',NULL,'异常批量删除','dba_zhang',24);
-- ---------------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_block_client //
CREATE PROCEDURE sp_block_client(
    IN  p_username     VARCHAR(64)  CHARACTER SET utf8mb4,
    IN  p_client_ip    VARCHAR(45)  CHARACTER SET utf8mb4,
    IN  p_client_port  INT,
    IN  p_reason       VARCHAR(500) CHARACTER SET utf8mb4,
    IN  p_operator     VARCHAR(64)  CHARACTER SET utf8mb4,
    IN  p_expire_hours INT
)
BEGIN
    DECLARE v_conn_id   INT UNSIGNED;
    DECLARE v_done      INT DEFAULT 0;
    DECLARE v_cur CURSOR FOR
        SELECT id FROM information_schema.processlist
        WHERE user = p_username
          AND host LIKE CONCAT(p_client_ip, '%');
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = 1;

    -- 1. 写入黑名单（已存在则更新）
    INSERT INTO client_blacklist (username, client_ip, client_port, reason, operator, expire_at, status)
    VALUES (p_username, p_client_ip, p_client_port, p_reason, p_operator,
            IF(p_expire_hours IS NULL, NULL, DATE_ADD(NOW(), INTERVAL p_expire_hours HOUR)),
            'active')
    ON DUPLICATE KEY UPDATE
        reason     = p_reason,
        operator   = p_operator,
        expire_at  = IF(p_expire_hours IS NULL, NULL, DATE_ADD(NOW(), INTERVAL p_expire_hours HOUR)),
        status     = 'active',
        created_at = NOW();

    -- 2. KILL 该用户从该 IP 的所有现有连接
    OPEN v_cur;
    read_loop: LOOP
        FETCH v_cur INTO v_conn_id;
        IF v_done THEN LEAVE read_loop; END IF;

        INSERT INTO block_audit_log (action, username, client_ip, client_port, connection_id, reason, operator)
        VALUES ('kill', p_username, p_client_ip, p_client_port, v_conn_id, p_reason, p_operator);

        SET @kill_sql = CONCAT('KILL ', v_conn_id);
        PREPARE stmt FROM @kill_sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END LOOP;
    CLOSE v_cur;

    -- 3. 记录封禁日志
    INSERT INTO block_audit_log (action, username, client_ip, client_port, reason, operator)
    VALUES ('block', p_username, p_client_ip, p_client_port, p_reason, p_operator);

    -- 4. 完成（执行结果已写入 block_audit_log 表，无需额外输出）
END //


-- ---------------------------------------------------------------------
-- 存储过程：sp_unblock_client
-- 调用示例：
--   CALL security.sp_unblock_client('app_user','10.0.0.5','dba_zhang');
-- ---------------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_unblock_client //
CREATE PROCEDURE sp_unblock_client(
    IN  p_username  VARCHAR(64),
    IN  p_client_ip VARCHAR(45),
    IN  p_operator  VARCHAR(64)
)
BEGIN
    UPDATE client_blacklist
    SET status = 'released'
    WHERE username = p_username
      AND client_ip = p_client_ip
      AND status = 'active';

    INSERT INTO block_audit_log (action, username, client_ip, reason, operator)
    VALUES ('unblock', p_username, p_client_ip, '手动解封', p_operator);

    -- 完成（执行结果已写入 block_audit_log 表，无需额外输出）
END //


-- ---------------------------------------------------------------------
-- 存储过程：sp_show_blacklist
-- ---------------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_show_blacklist //
CREATE PROCEDURE sp_show_blacklist()
BEGIN
    SELECT id, username, client_ip, client_port, reason, operator,
           created_at,
           IFNULL(expire_at, '永久') AS expire_at,
           IF(expire_at IS NOT NULL AND expire_at <= NOW(), '已过期', status) AS real_status
    FROM client_blacklist
    WHERE status = 'active'
    ORDER BY created_at DESC;
END //


-- ---------------------------------------------------------------------
-- 存储过程：sp_show_audit_log
-- 注意：LIMIT 使用变量需要 5.5.6+，如果环境是 5.5.5 请改用 PREPARE/EXECUTE
-- ---------------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_show_audit_log //
CREATE PROCEDURE sp_show_audit_log(
    IN p_limit INT
)
BEGIN
    SET p_limit = IFNULL(p_limit, 20);

    SELECT id, action, username, client_ip, client_port,
           connection_id, reason, operator, created_at
    FROM block_audit_log
    ORDER BY created_at DESC
    LIMIT p_limit;
END //

DELIMITER ;


-- =====================================================================
-- 第四部分：权限配置
-- =====================================================================
-- 说明：
--   5.5+ 方案使用 SELECT CASE WHEN + EXP(710)，以当前连接用户身份执行
--   因此业务用户需要 SELECT ON client_blacklist
--   管理存储过程（sp_block_client 等）由 DBA 调用，不需要额外授权
-- =====================================================================

-- ====== 请替换为你的实际业务账号 ======

-- 逐个授权（业务用户需要 SELECT 权限查黑名单表）
-- GRANT SELECT ON security.client_blacklist TO 'app_user'@'10.0.0.5';
-- GRANT SELECT ON security.client_blacklist TO 'app_user'@'10.0.0.6';
-- GRANT SELECT ON security.client_blacklist TO 'web_reader'@'10.0.0.%';

-- MySQL 8.0+ 可用角色方式
-- CREATE ROLE IF NOT EXISTS 'security_checker';
-- GRANT SELECT ON security.client_blacklist TO 'security_checker';
-- GRANT 'security_checker' TO 'app_user'@'10.0.0.5';
-- SET DEFAULT ROLE 'security_checker' TO 'app_user'@'10.0.0.5';

-- 给 DBA 管理账号完整权限（替换为你的 DBA 账号）
-- GRANT SELECT, INSERT, UPDATE, DELETE ON security.* TO 'dba_admin'@'localhost';

-- FLUSH PRIVILEGES;


-- =====================================================================
-- 第五部分：配置 init_connect
-- =====================================================================
-- 说明：
--   使用 SELECT CASE WHEN 语法，标准 SQL，可读性强
--   命中黑名单 → 执行 EXP(710) → ERROR 1690 (DOUBLE value is out of range)
--              → init_connect 失败 → 连接中止 → 客户端收到 ERROR 1184
--   未命中 → CASE 走 ELSE 分支返回 1 → init_connect 成功 → 连接放行
--
-- 兼容性：
--   EXP 溢出报错从 5.5.5 起可用，5.6 / 5.7 / 8.0 全系列无回归风险
--   EXP(710): e^710 ≈ 2.2×10³⁰⁸，刚好超过 DOUBLE 最大值（≈1.8×10³⁰⁸）
-- =====================================================================

-- 方式一：双引号版本（推荐，可读性好，无引号转义问题）
SET GLOBAL init_connect = "SELECT CASE WHEN EXISTS(SELECT 1 FROM security.client_blacklist WHERE username = SUBSTRING_INDEX(USER(),'@',1) AND client_ip = SUBSTRING_INDEX(USER(),'@',-1) AND status = 'active' AND (expire_at IS NULL OR expire_at > NOW())) THEN EXP(710) ELSE 1 END";

-- 方式二：单引号版本（如果环境不支持双引号）
-- SET GLOBAL init_connect = 'SELECT CASE WHEN EXISTS(SELECT 1 FROM security.client_blacklist WHERE username = SUBSTRING_INDEX(USER(),''@'',1) AND client_ip = SUBSTRING_INDEX(USER(),''@'',-1) AND status = ''active'' AND (expire_at IS NULL OR expire_at > NOW())) THEN EXP(710) ELSE 1 END';

-- 验证配置
SELECT @@global.init_connect AS init_connect_config;


-- =====================================================================
-- 第六部分：开启事件调度器（自动清理过期黑名单）
-- =====================================================================

SET GLOBAL event_scheduler = ON;

DROP EVENT IF EXISTS ev_auto_release_blacklist;
DELIMITER $$
CREATE EVENT ev_auto_release_blacklist
ON SCHEDULE EVERY 1 HOUR
DO
BEGIN
    -- 先记录审计日志（此时 status 仍为 active，确保只记录本次实际释放的记录）
    INSERT INTO security.block_audit_log (action, username, client_ip, reason, operator)
    SELECT 'auto_release', username, client_ip, '黑名单过期自动解封', 'system'
    FROM security.client_blacklist
    WHERE status = 'active'
      AND expire_at IS NOT NULL
      AND expire_at <= NOW();
    -- 再执行释放
    UPDATE security.client_blacklist
    SET status = 'released'
    WHERE status = 'active'
      AND expire_at IS NOT NULL
      AND expire_at <= NOW();
END $$
DELIMITER ;


-- =====================================================================
-- 第七部分：部署验证
-- =====================================================================

-- 验证表创建
SELECT '=== 表结构验证 ===' AS info;
SELECT TABLE_NAME FROM information_schema.TABLES
WHERE TABLE_SCHEMA = 'security';
-- 预期：client_blacklist, block_audit_log

-- 验证存储过程创建
SELECT '=== 存储过程验证 ===' AS info;
SELECT ROUTINE_NAME FROM information_schema.ROUTINES
WHERE ROUTINE_SCHEMA = 'security' AND ROUTINE_TYPE = 'PROCEDURE';
-- 预期：sp_block_client, sp_unblock_client, sp_show_blacklist, sp_show_audit_log

-- 验证事件创建
SELECT '=== 事件验证 ===' AS info;
SELECT EVENT_NAME, STATUS FROM information_schema.EVENTS
WHERE EVENT_SCHEMA = 'security';

-- 验证 init_connect 配置
SELECT '=== init_connect 配置 ===' AS info;
SELECT @@global.init_connect AS config;

-- 验证事件调度器状态
SELECT '=== 事件调度器状态 ===' AS info;
SELECT @@global.event_scheduler AS scheduler_status;

-- 部署完成提示
SELECT '========================================' AS info
UNION ALL SELECT 'MySQL 软阻断系统 v5.6-final 部署完成'
UNION ALL SELECT '阻断方式：SELECT CASE WHEN ... THEN EXP(710) ELSE 1 END'
UNION ALL SELECT '兼容版本：MySQL 5.5.5+ / 5.6 / 5.7 / 8.0 / MariaDB / Percona'
UNION ALL SELECT '========================================'
UNION ALL SELECT '下一步：'
UNION ALL SELECT '1. 给业务账号授权 SELECT ON security.client_blacklist'
UNION ALL SELECT '2. 将 init_connect 配置写入 my.cnf 持久化（推荐单引号版本）：'
UNION ALL SELECT '   init_connect=''SELECT CASE WHEN EXISTS(SELECT 1 FROM security.client_blacklist WHERE username = SUBSTRING_INDEX(USER(),''''@'''',1) AND client_ip = SUBSTRING_INDEX(USER(),''''@'''',-1) AND status = ''''active'''' AND (expire_at IS NULL OR expire_at > NOW())) THEN EXP(710) ELSE 1 END'''
UNION ALL SELECT '   注意：my.cnf 中 init_connect 必须用单引号包裹，内部单引号用 '' 转义'
UNION ALL SELECT '3. 将 event_scheduler=ON 写入 my.cnf 持久化'
UNION ALL SELECT '4. 执行测试：CALL security.sp_block_client(...)'
UNION ALL SELECT '========================================';


-- =====================================================================
-- 附录：my.cnf 持久化配置示例
-- =====================================================================
-- [mysqld]
-- # 软阻断 init_connect 配置（v5.6-final：SELECT CASE WHEN ... THEN EXP(710) ELSE 1 END）
-- init_connect='SELECT CASE WHEN EXISTS(SELECT 1 FROM security.client_blacklist WHERE username = SUBSTRING_INDEX(USER(),''@'',1) AND client_ip = SUBSTRING_INDEX(USER(),''@'',-1) AND status = ''active'' AND (expire_at IS NULL OR expire_at > NOW())) THEN EXP(710) ELSE 1 END'
--
-- # 事件调度器
-- event_scheduler=ON
--
-- # 注意：
-- # my.cnf 值用单引号包裹，内部单引号必须用 '' 转义（两个单引号）
-- # 不要用双引号，否则 MySQL 解析 my.cnf 时可能出现问题
-- =====================================================================
