-- =====================================================================
-- MySQL 软阻断系统部署脚本 — 5.1 专用版
-- 功能：基于 init_connect + 黑名单表实现 user@ip 粒度的客户端软阻断
-- 核心方案：存储过程 search.check_blacklist_51() + INSERT 主键冲突触发错误
--          init_connect 执行 CALL，命中黑名单则 INSERT 重复主键 → ERROR 1062 → 连接拒绝
-- 版本：v5.1-final
-- 日期：2026-08-10
-- 兼容：MySQL 5.0.3 ~ 5.1.x
-- 使用：用 root（SUPER 权限）账号连接 MySQL 后执行本脚本
--   mysql -u root -p < 02-部署脚本-5.1版本.sql
-- =====================================================================
--
-- 版本历史：
--   v1.0  SLEEP(86400)        -> 只延迟不报错 X
--   v3.0  inline REGEXP       -> 引号嵌套问题 X
--   v4.0  存储过程+SIGNAL     -> 5.1 不支持 SIGNAL X
--   v5.1  存储过程+主键冲突   -> 5.1 最终方案 OK
--
-- 核心原理：
--   存储过程 check_blacklist_51() 检查黑名单表
--   命中 → INSERT INTO block_trigger VALUES (1)
--         → ERROR 1062 (Duplicate entry，主键已存在)
--         → init_connect 失败 → 连接被中止
--         → 客户端收到 ERROR 1184 (init_connect command failed)
--
-- 为什么用主键冲突：
--   1. ERROR 1062 是硬约束违规，不受 SQL mode 影响
--   2. 不需要 SIGNAL 语句（5.1 不支持）
--   3. 不需要 EXP 溢出报错（5.1 不报错）
--   4. SQL SECURITY DEFINER 在 5.0.3+ 可用，权限隔离完美
--
-- 注意：
--   1. 存储过程中不声明 HANDLER for 1062，错误直接传播
--   2. 如果 MySQL 5.1 打了 Bug #47032 补丁（5.1.62+），CALL 中的错误可能被吞噬
--      此时需改用 inline INSERT...SELECT 方案（见部署文档）
--   3. SUPER 权限用户跳过 init_connect，确保 DBA 不会被锁
-- =====================================================================


-- =====================================================================
-- 第一部分：环境检查
-- =====================================================================

-- 检查 MySQL 版本（需要 5.0.3+，SQL SECURITY DEFINER 于 5.0.3 引入）
SELECT CONCAT('MySQL 版本: ', VERSION()) AS env_check;
-- 如果版本 >= 5.5，请改用 5.5+ 部署脚本（SELECT CASE WHEN + EXP(710) 方案）

-- 检查当前 init_connect 是否已有配置
SELECT CONCAT('当前 init_connect: ',
    IFNULL(@@global.init_connect, '(空)')) AS env_check;

-- 列出拥有 SUPER 权限的账号（这些账号会跳过 init_connect）
SELECT user, host, Super_priv
FROM mysql.user
WHERE Super_priv = 'Y';

-- 如果上述查询无结果，请确保至少保留一个 SUPER 账号作为应急入口


-- =====================================================================
-- 第二部分：创建数据库和表
-- =====================================================================

CREATE DATABASE IF NOT EXISTS security;
USE security;

-- 黑名单主表
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='MySQL 客户端软阻断黑名单表';

-- 操作审计日志表
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='软阻断操作审计日志';

-- 错误触发表（5.1 专用）
-- 只有一行 id=1，INSERT 相同值触发 ERROR 1062
CREATE TABLE IF NOT EXISTS block_trigger (
    id INT PRIMARY KEY
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='错误触发辅助表（5.1版本专用）';

-- 初始化触发表数据（确保主键冲突可触发）
INSERT IGNORE INTO security.block_trigger (id) VALUES (1);


-- =====================================================================
-- 第三部分：创建存储过程
-- =====================================================================

USE security;
DELIMITER //

-- ---------------------------------------------------------------------
-- 存储过程：check_blacklist_51（核心阻断过程 — 5.1 专用）
-- 功能：检查当前连接用户是否在黑名单中，命中则 INSERT 主键冲突拒绝连接
-- 由 init_connect 调用：SET GLOBAL init_connect = 'CALL security.check_blacklist_51();'
--
-- 权限说明：
--   存储过程显式声明 SQL SECURITY DEFINER，以创建者（root）身份执行
--   业务用户只需 EXECUTE ON PROCEDURE security.check_blacklist_51
--   不需要 SELECT ON security.client_blacklist（权限隔离）
--
-- 阻断原理：
--   INSERT INTO block_trigger VALUES (1) → 主键冲突 → ERROR 1062
--   → 存储过程未声明 HANDLER for 1062 → 错误传播到 init_connect
--   → init_connect 失败 → 连接被中止 → 客户端收到 ERROR 1184
--
-- 注意：
--   1. 不要在此过程中加 DECLARE HANDLER FOR 1062，否则错误被捕获不会传播
--   2. USER() 在 DEFINER 过程中返回连接客户端的身份（不是 DEFINER）
--   3. 如果在 5.1.62+ 上 CALL 错误被吞噬，请改用 inline INSERT...SELECT 方案
-- ---------------------------------------------------------------------
DROP PROCEDURE IF EXISTS check_blacklist_51 //
CREATE PROCEDURE security.check_blacklist_51()
SQL SECURITY DEFINER
BEGIN
    DECLARE v_blocked INT DEFAULT 0;

    -- 检查黑名单
    SELECT COUNT(*) INTO v_blocked
    FROM security.client_blacklist
    WHERE username = SUBSTRING_INDEX(USER(), '@', 1)
      AND client_ip = SUBSTRING_INDEX(USER(), '@', -1)
      AND status = 'active'
      AND (expire_at IS NULL OR expire_at > NOW());

    -- 命中黑名单 → 触发主键冲突 → ERROR 1062
    IF v_blocked > 0 THEN
        INSERT INTO security.block_trigger (id) VALUES (1);
    END IF;
END //


-- ---------------------------------------------------------------------
-- 存储过程：sp_block_client
-- 功能：写入黑名单 + KILL 现有连接 + 记录审计日志
--       关键：使用 KILL @var 而非 PREPARE/EXECUTE，避免 5.1 的 ERROR 1312
-- 参数：
--   p_username     - 要封禁的 MySQL 用户名
--   p_client_ip    - 要封禁的客户端 IP
--   p_client_port  - 客户端源端口（不确定可传 NULL，仅记录用）
--   p_reason       - 封禁原因
--   p_operator     - 操作人（DBA 账号名）
--   p_expire_hours - 过期小时数（NULL=永久，正整数=N小时后自动解封）
-- 调用示例：
--   CALL security.sp_block_client('app_user','10.0.0.5',54321,'非法DROP TABLE','dba_zhang',NULL);
--   CALL security.sp_block_client('app_user','10.0.0.5',NULL,'异常批量删除','dba_zhang',24);
--  注意：MySQL 5.1 中游标 + PREPARE/EXECUTE 组合会导致 ERROR 1312。
--  因此 KILL 逻辑使用 "KILL @var" 直接执行（KILL 语句原生支持用户变量），
--  不经过 PREPARE/EXECUTE，彻底避免编译器标记"可能返回结果集"。
DROP PROCEDURE IF EXISTS sp_block_client //
CREATE PROCEDURE sp_block_client(
    IN  p_username     VARCHAR(64),
    IN  p_client_ip    VARCHAR(45),
    IN  p_client_port  INT,
    IN  p_reason       VARCHAR(500),
    IN  p_operator     VARCHAR(64),
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
    --    关键：使用 KILL @var 而非 PREPARE/EXECUTE，避免 5.1 的 ERROR 1312
    OPEN v_cur;
    read_loop: LOOP
        FETCH v_cur INTO v_conn_id;
        IF v_done THEN LEAVE read_loop; END IF;

        INSERT INTO block_audit_log (action, username, client_ip, client_port, connection_id, reason, operator)
        VALUES ('kill', p_username, p_client_ip, p_client_port, v_conn_id, p_reason, p_operator);

        SET @kill_id = v_conn_id;
        KILL @kill_id;
    END LOOP;
    CLOSE v_cur;

    -- 3. 记录封禁日志
    INSERT INTO block_audit_log (action, username, client_ip, client_port, reason, operator)
    VALUES ('block', p_username, p_client_ip, p_client_port, p_reason, p_operator);
END //


-- ---------------------------------------------------------------------
-- 存储过程：sp_unblock_client（同 v4.0）
-- 功能：解封客户端
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
-- 存储过程：sp_show_blacklist（同 v4.0）
-- 功能：查看当前活跃的黑名单
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
-- 功能：查看审计日志
-- 注意：MySQL 5.1 不支持 LIMIT 后直接使用变量（5.5.6 才修复），
--       必须用 PREPARE/EXECUTE 动态 SQL 绕过
-- ---------------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_show_audit_log //
CREATE PROCEDURE sp_show_audit_log(
    IN p_limit INT
)
BEGIN
    SET p_limit = IFNULL(p_limit, 20);

    SET @sql = CONCAT('
        SELECT id, action, username, client_ip, client_port,
               connection_id, reason, operator, created_at
        FROM block_audit_log
        ORDER BY created_at DESC
        LIMIT ', p_limit);

    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END //

DELIMITER ;


-- =====================================================================
-- 第四部分：权限配置
-- =====================================================================
-- 说明：
-- 存储过程 check_blacklist_51 定义 SQL SECURITY DEFINER
-- 业务用户只需 EXECUTE 权限，不需要 SELECT ON client_blacklist（权限隔离）
-- =====================================================================

-- ====== 请替换为你的实际业务账号 ======

-- 逐个授权（推荐）
-- GRANT EXECUTE ON PROCEDURE security.check_blacklist_51 TO 'app_user'@'10.0.0.5';
-- GRANT EXECUTE ON PROCEDURE security.check_blacklist_51 TO 'app_user'@'10.0.0.6';
-- GRANT EXECUTE ON PROCEDURE security.check_blacklist_51 TO 'web_reader'@'10.0.0.%';

-- 给 DBA 管理账号完整权限（替换为你的 DBA 账号）
-- GRANT SELECT, INSERT, UPDATE, DELETE ON security.* TO 'dba_admin'@'localhost';

-- FLUSH PRIVILEGES;


-- =====================================================================
-- 第五部分：配置 init_connect
-- =====================================================================
-- 说明：
-- 1. init_connect 在每次新连接认证通过后自动执行
-- 2. CALL security.check_blacklist_51()：
--    命中黑名单 → INSERT 主键冲突 → ERROR 1062 → init_connect 失败 → 连接中止
--    未命中 → 过程正常结束 → init_connect 成功 → 连接放行
-- 3. SUPER 权限用户跳过 init_connect，确保 DBA 不会被锁
-- =====================================================================

SET GLOBAL init_connect = 'CALL security.check_blacklist_51();';

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
-- 预期：client_blacklist, block_audit_log, block_trigger

-- 验证 block_trigger 数据
SELECT '=== block_trigger 表数据 ===' AS info;
SELECT * FROM security.block_trigger;
-- 预期：id=1 有一条记录

-- 验证存储过程创建
SELECT '=== 存储过程验证 ===' AS info;
SELECT ROUTINE_NAME FROM information_schema.ROUTINES
WHERE ROUTINE_SCHEMA = 'security' AND ROUTINE_TYPE = 'PROCEDURE';
-- 预期：check_blacklist_51, sp_block_client, sp_unblock_client,
--       sp_show_blacklist, sp_show_audit_log

-- 验证事件创建
SELECT '=== 事件验证 ===' AS info;
SELECT EVENT_NAME, STATUS FROM information_schema.EVENTS
WHERE EVENT_SCHEMA = 'security';

-- 验证 init_connect 配置
SELECT '=== init_connect 配置 ===' AS info;
SELECT @@global.init_connect AS config;
-- 预期：CALL security.check_blacklist_51();

-- 部署完成提示
SELECT '========================================' AS info
UNION ALL SELECT 'MySQL 软阻断系统 v5.1-final 部署完成'
UNION ALL SELECT '阻断方式：存储过程 + INSERT 主键冲突 → ERROR 1062'
UNION ALL SELECT '兼容版本：MySQL 5.0.3 ~ 5.1.x'
UNION ALL SELECT '========================================'
UNION ALL SELECT '下一步：'
UNION ALL SELECT '1. 给业务账号授权 EXECUTE ON PROCEDURE security.check_blacklist_51'
UNION ALL SELECT '2. 将 init_connect 配置写入 my.cnf 持久化：'
UNION ALL SELECT "   init_connect='CALL security.check_blacklist_51();'"
UNION ALL SELECT '3. 将 event_scheduler=ON 写入 my.cnf 持久化'
UNION ALL SELECT '4. 执行测试：CALL security.sp_block_client(...)'
UNION ALL SELECT '========================================';
