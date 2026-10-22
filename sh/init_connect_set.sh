#!/bin/bash
# =====================================================================
# MySQL 软阻断系统 — 一键部署/卸载脚本 (v1.1)
#
# 功能：
#   基于 init_connect 方案，对 MySQL 服务器一键实施软阻断系统：
#   1. 自动检测 MySQL 版本并选择对应方案（5.1 / 5.5+）
#   2. 自动创建 security 库、黑名单表、审计表、存储过程、自动解封事件
#   3. 自动查询当前普通用户并授予阻断检查所需权限（并打印授权 SQL）
#   4. 自动配置 init_connect + 事件调度器
#   5. 询问后自动写入 my.cnf 持久化（可选）
#   6. 部署验证并打印分步骤执行结果
#   7. 支持 --uninstall 一键卸载（回滚 init_connect、REVOKE 权限、DROP 对象）
#
# 用法：
#   ./init_connect_set.sh.sh [-h host] [-P port] [-u user] [-p password] [--uninstall]
#   示例：
#     ./init_connect_set.sh.sh                                # 本地 socket + 交互输入密码
#     ./init_connect_set.sh.sh -u root -p 'MyPass!23'
#     ./init_connect_set.sh.sh -h 10.0.0.8 -P 3306 -u dba_root -p 'xxx'
#     ./init_connect_set.sh.sh -u root -p 'xxx' --uninstall   # 卸载
#   注意：管理员账号需具备 SUPER 权限（设置/清除 init_connect 必需）
#
# 环境要求：
#   - 本机已安装 mysql 客户端（mysql 命令可用）
#   - 目标 MySQL：5.0.3+ / 5.5.5+ / 5.6 / 5.7 / 8.0 / MariaDB 10.0+
#   - 已实测环境：MySQL 5.1 + MySQL 5.7
#   - MySQL 8.0：代码层面兼容，尚未实测，建议首次部署后做完整验证
#   - my.cnf 持久化（5.5+ 方案单引号转义）：尚未通过"写入→重启→检查"完整链路验证
#
# 安全说明：
#   - 密码通过临时 defaults-extra-file 传入，不出现在命令行（ps 不可见）
#   - 脚本退出自动删除临时凭据文件
#   - 关键顺序：先 GRANT 授权、最后才设置 init_connect（防止未授权用户全部被拒）
#   - SUPER 权限用户跳过 init_connect，部署全程有应急入口
#
# SQL 内容与已验证部署脚本保持同步：
#   - 5.1 方案  : 02-部署脚本-5.1版本.sql
#   - 5.5+ 方案 : 03-部署脚本-5.5及以上版本.sql
# =====================================================================

set -u
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

MYSQL_HOST=""
MYSQL_PORT="3306"
MYSQL_USER=""
MYSQL_PASS=""
UNINSTALL=0

# 解析 --uninstall 长选项（getopts 不支持长选项，提前提取）
NEW_ARGS=()
for arg in "$@"; do
    if [ "$arg" = "--uninstall" ]; then
        UNINSTALL=1
    else
        NEW_ARGS+=("$arg")
    fi
done
if [ ${#NEW_ARGS[@]} -gt 0 ]; then
    set -- "${NEW_ARGS[@]}"
else
    set --   # 无剩余参数时显式清空，避免 getopts 撞上已提取的 --uninstall
fi

usage() {
    cat <<EOF
用法: $0 [-h host] [-P port] [-u user] [-p password] [--uninstall]

选项:
  -h host       MySQL 主机地址（默认: 本地 socket）
  -P port       MySQL 端口（默认: 3306）
  -u user       MySQL 管理员用户名（必填，需 SUPER 权限）
  -p pass       MySQL 管理员密码（不传则交互输入，隐藏回显）
  --uninstall   卸载模式：清除 init_connect、REVOKE 权限、DROP 所有对象
EOF
    exit 0
}

while getopts "h:P:u:p:" opt; do
    case "$opt" in
        h) MYSQL_HOST="$OPTARG" ;;
        P) MYSQL_PORT="$OPTARG" ;;
        u) MYSQL_USER="$OPTARG" ;;
        p) MYSQL_PASS="$OPTARG" ;;
        *) usage ;;
    esac
done

[ -z "$MYSQL_USER" ] && { echo "错误: 必须指定管理员用户名 (-u)"; usage; }
if [ -z "$MYSQL_PASS" ]; then
    read -r -s -p "请输入 MySQL 管理员 ($MYSQL_USER) 密码: " MYSQL_PASS
    echo ""
    [ -z "$MYSQL_PASS" ] && { echo "错误: 密码不能为空"; exit 1; }
fi

command -v mysql >/dev/null 2>&1 || { echo "错误: 未找到 mysql 客户端，请先安装"; exit 1; }

# ---------- 临时凭据文件（避免密码出现在命令行） ----------
TMP_DEFAULTS="$(mktemp)"
chmod 600 "$TMP_DEFAULTS"
{
    echo "[client]"
    echo "user=${MYSQL_USER}"
    echo "password=${MYSQL_PASS}"
    echo "port=${MYSQL_PORT}"
    [ -n "$MYSQL_HOST" ] && echo "host=${MYSQL_HOST}"
} > "$TMP_DEFAULTS"
trap 'rm -f "$TMP_DEFAULTS"' EXIT

MYSQL_CMD=(mysql --defaults-extra-file="$TMP_DEFAULTS" --batch --raw --skip-column-names)
mysql_run() { "${MYSQL_CMD[@]}" "$@"; }

# ---------- 输出与结果记录 ----------
ok()   { echo -e "  ${GREEN}[OK]${NC}   $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
info() { echo -e "  ${CYAN}----${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }

declare -a RESULTS=()
rec_ok()   { RESULTS+=("OK|$1"); }
rec_fail() { RESULTS+=("FAIL|$1"); }

# =====================================================================
# 卸载模式
# =====================================================================
if [ "$UNINSTALL" = "1" ]; then
    echo ""
    echo "============================================================"
    echo " MySQL 软阻断系统 — 卸载"
    echo " 目标: ${MYSQL_HOST:-localhost(socket)}:${MYSQL_PORT}  管理员: ${MYSQL_USER}"
    echo "============================================================"

    echo ""
    echo "==> [1/6] 连接测试与权限检查"
    if ! mysql_run -e "SELECT 1" >/dev/null 2>&1; then
        fail "无法连接 MySQL，请检查账号、密码、网络"
        exit 1
    fi
    ok "MySQL 连接成功"

    HAS_SUPER=$(mysql_run -e "SELECT IF(EXISTS(SELECT 1 FROM mysql.user WHERE User=SUBSTRING_INDEX(CURRENT_USER(),'@',1) AND Host=SUBSTRING_INDEX(CURRENT_USER(),'@',-1) AND Super_priv='Y'),'YES','NO')" 2>/dev/null)
    if [ "$HAS_SUPER" != "YES" ]; then
        fail "当前账号不具备 SUPER 权限，无法清除 init_connect"
        exit 1
    fi
    ok "SUPER 权限确认"

    # GRANT OPTION 检查（REVOKE 必需，SUPER 不等于 GRANT OPTION）
    HAS_GRANT_OPT=$(mysql_run -e "SELECT IF(EXISTS(SELECT 1 FROM mysql.user WHERE User=SUBSTRING_INDEX(CURRENT_USER(),'@',1) AND Host=SUBSTRING_INDEX(CURRENT_USER(),'@',-1) AND Grant_priv='Y'),'YES','NO')" 2>/dev/null)
    if [ "$HAS_GRANT_OPT" != "YES" ]; then
        fail "当前账号不具备 GRANT OPTION 权限，无法执行 REVOKE"
        echo "  请改用 root 或具备 GRANT OPTION 的账号运行"
        exit 1
    fi
    ok "GRANT OPTION 权限确认"
    rec_ok "连接测试与权限检查"

    echo ""
    echo "==> [2/6] 清除 init_connect（关闭阻断总开关）"
    CUR_INIT=$(mysql_run -e "SELECT @@global.init_connect" 2>/dev/null)
    if [ -z "$CUR_INIT" ] || [ "$CUR_INIT" = "NULL" ]; then
        info "init_connect 当前为空，无需清除"
    else
        echo "  当前值: $CUR_INIT"
        if mysql_run -e "SET GLOBAL init_connect = '';" >/dev/null 2>&1; then
            ok "init_connect 已清除"
        else
            fail "清除 init_connect 失败"; rec_fail "清除 init_connect"; exit 1
        fi
    fi
    rec_ok "清除 init_connect"

    echo ""
    echo "==> [3/6] 回收普通用户权限"
    REVOKE_CNT=0
    REVOKE_FAIL=0

    # 查询 procs_priv（5.1 方案授权的 EXECUTE 权限）
    PROCS_PRIV=$(mysql_run -e "
        SELECT CONCAT(QUOTE(User), ',', QUOTE(Host))
        FROM mysql.procs_priv
        WHERE Db = 'security'
          AND Routine_name = 'check_blacklist_51'" 2>/dev/null)
    if [ -n "$PROCS_PRIV" ]; then
        while IFS= read -r line; do
            u="${line%%,*}"; h="${line##*,}"
            u="${u//\'/}"; h="${h//\'/}"
            [ -z "$u" ] && continue
            RSQL="REVOKE EXECUTE ON PROCEDURE security.check_blacklist_51 FROM '$u'@'$h';"
            echo "      REVOKE EXECUTE: '$u'@'$h'"
            if ERR_MSG=$(mysql_run -e "$RSQL" 2>&1); then
                REVOKE_CNT=$((REVOKE_CNT+1))
            else
                REVOKE_FAIL=$((REVOKE_FAIL+1))
                fail "回收失败: '$u'@'$h' -> $(echo "$ERR_MSG" | tail -1)"
            fi
        done <<< "$PROCS_PRIV"
    fi

    # 查询 tables_priv（5.5+ 方案授权的 SELECT 权限）
    TABLES_PRIV=$(mysql_run -e "
        SELECT CONCAT(QUOTE(User), ',', QUOTE(Host))
        FROM mysql.tables_priv
        WHERE Db = 'security'
          AND Table_name = 'client_blacklist'" 2>/dev/null)
    if [ -n "$TABLES_PRIV" ]; then
        while IFS= read -r line; do
            u="${line%%,*}"; h="${line##*,}"
            u="${u//\'/}"; h="${h//\'/}"
            [ -z "$u" ] && continue
            RSQL="REVOKE SELECT ON security.client_blacklist FROM '$u'@'$h';"
            echo "      REVOKE SELECT: '$u'@'$h'"
            if ERR_MSG=$(mysql_run -e "$RSQL" 2>&1); then
                REVOKE_CNT=$((REVOKE_CNT+1))
            else
                REVOKE_FAIL=$((REVOKE_FAIL+1))
                fail "回收失败: '$u'@'$h' -> $(echo "$ERR_MSG" | tail -1)"
            fi
        done <<< "$TABLES_PRIV"
    fi

    mysql_run -e "FLUSH PRIVILEGES" >/dev/null 2>&1
    if [ "$REVOKE_CNT" -gt 0 ] || [ "$REVOKE_FAIL" -gt 0 ]; then
        if [ "$REVOKE_FAIL" -gt 0 ]; then
            fail "权限回收：成功 $REVOKE_CNT 个，失败 $REVOKE_FAIL 个"
            rec_fail "回收权限（$REVOKE_FAIL 个失败）"
        else
            ok "权限回收完成：$REVOKE_CNT 个账号"
            rec_ok "回收权限（$REVOKE_CNT 个账号）"
        fi
    else
        info "未发现需要回收的权限"
        rec_ok "回收权限（无权限需回收）"
    fi

    echo ""
    echo "==> [4/6] 删除事件和存储过程"
    mysql_run -e "DROP EVENT IF EXISTS security.ev_auto_release_blacklist;" >/dev/null 2>&1
    ok "事件 ev_auto_release_blacklist 已删除"

    for proc in check_blacklist_51 sp_block_client sp_unblock_client sp_show_blacklist sp_show_audit_log; do
        mysql_run -e "DROP PROCEDURE IF EXISTS security.$proc;" >/dev/null 2>&1
    done
    ok "存储过程已删除（check_blacklist_51, sp_block_client, sp_unblock_client, sp_show_blacklist, sp_show_audit_log）"
    rec_ok "删除事件和存储过程"

    echo ""
    echo "==> [5/6] 删除 security 数据库"
    if mysql_run -e "DROP DATABASE IF EXISTS security;" >/dev/null 2>&1; then
        ok "security 数据库已删除（含所有表）"
        rec_ok "删除 security 数据库"
    else
        fail "删除 security 数据库失败"
        rec_fail "删除 security 数据库"
    fi

    echo ""
    echo "==> [6/6] my.cnf 清理提示"
    echo "  如曾通过脚本写入 my.cnf，请手动删除以下行（搜索 '软阻断'）："
    echo "    init_connect=..."
    echo "    event_scheduler=ON（如无其他事件依赖）"
    echo "  或检查备份文件: my.cnf.bak.*"
    rec_ok "my.cnf 清理提示"

    echo ""
    echo "============================================================"
    echo " 卸载结果汇总"
    echo "============================================================"
    for r in "${RESULTS[@]}"; do
        st="${r%%|*}"; msg="${r#*|}"
        if [ "$st" = "OK" ]; then echo -e "  ${GREEN}[OK]${NC}   $msg"; else echo -e "  ${RED}[FAIL]${NC} $msg"; fi
    done
    echo "============================================================"
    echo " 卸载后普通用户可正常连接（init_connect 已清除）"
    echo "============================================================"
    exit 0
fi

# =====================================================================
# 部署模式
# =====================================================================
echo ""
echo "============================================================"
echo " MySQL 软阻断系统一键部署"
echo " 目标: ${MYSQL_HOST:-localhost(socket)}:${MYSQL_PORT}  管理员: ${MYSQL_USER}"
echo "============================================================"

# =====================================================================
# 步骤 1: 连接测试 + SUPER 权限检查
# =====================================================================
echo ""
echo "==> [1/8] 连接测试与权限检查"
if ! mysql_run -e "SELECT 1" >/dev/null 2>&1; then
    fail "无法连接 MySQL，请检查账号、密码、网络"
    echo "  可能原因: 密码错误 / 主机不可达 / 账号无远程登录权限"
    exit 1
fi
ok "MySQL 连接成功"

HAS_SUPER=$(mysql_run -e "SELECT IF(EXISTS(SELECT 1 FROM mysql.user WHERE User=SUBSTRING_INDEX(CURRENT_USER(),'@',1) AND Host=SUBSTRING_INDEX(CURRENT_USER(),'@',-1) AND Super_priv='Y'),'YES','NO')" 2>/dev/null)
if [ "$HAS_SUPER" != "YES" ]; then
    fail "当前账号 ${MYSQL_USER} 不具备 SUPER 权限，无法设置 init_connect"
    exit 1
fi
ok "SUPER 权限确认（可设置 init_connect）"

# GRANT OPTION 权限检查（GRANT/REVOKE 必需，SUPER 不等于 GRANT OPTION）
HAS_GRANT_OPT=$(mysql_run -e "SELECT IF(EXISTS(SELECT 1 FROM mysql.user WHERE User=SUBSTRING_INDEX(CURRENT_USER(),'@',1) AND Host=SUBSTRING_INDEX(CURRENT_USER(),'@',-1) AND Grant_priv='Y'),'YES','NO')" 2>/dev/null)
if [ "$HAS_GRANT_OPT" != "YES" ]; then
    fail "当前账号 ${MYSQL_USER} 仅有 SUPER、无 GRANT OPTION 权限，无法执行 GRANT/REVOKE"
    echo "  请改用 root 或具备 GRANT OPTION 的账号运行本脚本"
    exit 1
fi
ok "GRANT OPTION 权限确认（可执行授权/回收）"
rec_ok "连接测试与权限检查"

# =====================================================================
# 步骤 2: 版本检测 → 方案分支
# =====================================================================
echo ""
echo "==> [2/8] 版本检测"
VERSION_STR=$(mysql_run -e "SELECT VERSION()")
BASE="${VERSION_STR%%-*}"
IS_MARIA="no"
case "$VERSION_STR" in
    *[Mm]aria*) IS_MARIA="yes" ;;
esac
IFS='.' read -r MAJOR MINOR PATCH <<< "$BASE"
MAJOR=${MAJOR:-0}; MINOR=${MINOR:-0}; PATCH=${PATCH:-0}
ok "MySQL 版本: ${VERSION_STR}"

SCHEME=""
if [ "$IS_MARIA" = "yes" ]; then
    if [ "$MAJOR" -ge 10 ]; then
        SCHEME="55"
        info "MariaDB ${BASE} → 采用 5.5+ 方案 (SELECT CASE WHEN + EXP(710))"
    else
        warn "MariaDB ${BASE} 版本过低，EXP(710) 不可用，请人工评估部署 5.1 方案"
        exit 1
    fi
else
    if [ "$MAJOR" -lt 5 ]; then
        fail "MySQL 版本过低（${BASE}），方案要求 5.0.3+"
        exit 1
    elif [ "$MAJOR" -eq 5 ] && [ "$MINOR" -lt 5 ]; then
        SCHEME="51"
        info "MySQL ${BASE} → 采用 5.1 方案 (CALL + 主键冲突 ERROR 1062)"
        if [ "$MINOR" -eq 1 ] && [ "$PATCH" -ge 62 ]; then
            warn "5.1.62+ 已修复 Bug #47032，CALL 错误可能被吞噬，请部署后实测封禁效果"
        fi
    elif [ "$MAJOR" -eq 5 ] && [ "$MINOR" -eq 5 ] && [ "$PATCH" -lt 5 ]; then
        warn "MySQL 5.5.0~5.5.4 EXP(710) 尚不可用，改用 5.1 方案 (CALL + 主键冲突)"
        SCHEME="51"
    else
        SCHEME="55"
        info "MySQL ${BASE} → 采用 5.5+ 方案 (SELECT CASE WHEN + EXP(710) ERROR 1690)"
    fi
fi
rec_ok "版本检测（${VERSION_STR} → ${SCHEME} 方案）"

# =====================================================================
# 步骤 3: 环境检查（现有 init_connect / SUPER 应急账号）
# =====================================================================
echo ""
echo "==> [3/8] 环境检查"
CUR_INIT=$(mysql_run -e "SELECT @@global.init_connect" 2>/dev/null)
if [ -n "$CUR_INIT" ] && [ "$CUR_INIT" != "NULL" ]; then
    warn "当前已存在 init_connect 配置，本次部署将覆盖:"
    echo "    $CUR_INIT"
    read -r -t 30 -p "    确认继续覆盖？[y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { echo "已取消部署"; exit 1; }
else
    ok "当前 init_connect 为空，无覆盖风险"
fi

SUPER_USERS=$(mysql_run -e "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE Super_priv='Y' ORDER BY User" 2>/dev/null)
if [ -z "$SUPER_USERS" ]; then
    fail "未找到任何 SUPER 权限账号，部署后无应急入口，已中止"
    exit 1
fi
ok "SUPER 应急账号确认（部署后不受 init_connect 影响）:"
while IFS= read -r su; do echo "      - $su"; done <<< "$SUPER_USERS"
rec_ok "环境检查"

# =====================================================================
# 步骤 4: 部署核心对象（建库/建表/存储过程/事件）
# =====================================================================
echo ""
echo "==> [4/8] 创建数据库对象（security 库、表、存储过程、自动解封事件）"
if [ "$SCHEME" = "51" ]; then
    if mysql_run <<'SQL_51'
-- ============ 5.1 方案：建库建表 ============
CREATE DATABASE IF NOT EXISTS security;
USE security;

CREATE TABLE IF NOT EXISTS client_blacklist (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(64)  NOT NULL COMMENT 'MySQL 用户名（不含@host部分）',
    client_ip   VARCHAR(45)  NOT NULL COMMENT '客户端 IP 地址',
    client_port INT UNSIGNED NULL     COMMENT '客户端源端口（可选，仅记录用）',
    reason      VARCHAR(500) NOT NULL COMMENT '封禁原因',
    operator    VARCHAR(64)  NOT NULL COMMENT '操作人 DBA 账号名',
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '封禁时间',
    expire_at   TIMESTAMP    NULL DEFAULT NULL COMMENT '过期时间 NULL=永久封禁',
    status      ENUM('active','released') NOT NULL DEFAULT 'active' COMMENT '黑名单状态',
    UNIQUE KEY uk_user_ip_port (username, client_ip, client_port),
    KEY idx_status_expire (status, expire_at),
    KEY idx_ip (client_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='MySQL 客户端软阻断黑名单表';

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

CREATE TABLE IF NOT EXISTS block_trigger (
    id INT PRIMARY KEY
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='错误触发辅助表（5.1版本专用）';

INSERT IGNORE INTO security.block_trigger (id) VALUES (1);

-- ============ 5.1 方案：存储过程 ============
USE security;
DELIMITER //

DROP PROCEDURE IF EXISTS check_blacklist_51 //
CREATE PROCEDURE security.check_blacklist_51()
SQL SECURITY DEFINER
BEGIN
    DECLARE v_blocked INT DEFAULT 0;
    SELECT COUNT(*) INTO v_blocked
    FROM security.client_blacklist
    WHERE username = SUBSTRING_INDEX(USER(), '@', 1)
      AND client_ip = SUBSTRING_INDEX(USER(), '@', -1)
      AND status = 'active'
      AND (expire_at IS NULL OR expire_at > NOW());
    IF v_blocked > 0 THEN
        INSERT INTO security.block_trigger (id) VALUES (1);
    END IF;
END //

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

    INSERT INTO block_audit_log (action, username, client_ip, client_port, reason, operator)
    VALUES ('block', p_username, p_client_ip, p_client_port, p_reason, p_operator);
END //

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
END //

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

-- ============ 5.1 方案：自动解封事件 ============
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
SQL_51
    then ok "5.1 方案对象创建完成"
    else fail "5.1 方案对象创建失败，请检查上方错误输出"; rec_fail "部署核心对象"; exit 1; fi
else
    if mysql_run <<'SQL_55'
-- ============ 5.5+ 方案：建库建表 ============
CREATE DATABASE IF NOT EXISTS security
    DEFAULT CHARACTER SET utf8mb4
    COLLATE utf8mb4_general_ci;
USE security;

CREATE TABLE IF NOT EXISTS client_blacklist (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(64)  NOT NULL COMMENT 'MySQL 用户名（不含@host部分）',
    client_ip   VARCHAR(45)  NOT NULL COMMENT '客户端 IP 地址',
    client_port INT UNSIGNED NULL     COMMENT '客户端源端口（可选，仅记录用）',
    reason      VARCHAR(500) NOT NULL COMMENT '封禁原因',
    operator    VARCHAR(64)  NOT NULL COMMENT '操作人 DBA 账号名',
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '封禁时间',
    expire_at   TIMESTAMP    NULL DEFAULT NULL COMMENT '过期时间 NULL=永久封禁',
    status      ENUM('active','released') NOT NULL DEFAULT 'active' COMMENT '黑名单状态',
    UNIQUE KEY uk_user_ip_port (username, client_ip, client_port),
    KEY idx_status_expire (status, expire_at),
    KEY idx_ip (client_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='MySQL 客户端软阻断黑名单表';

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

-- ============ 5.5+ 方案：存储过程 ============
USE security;
DELIMITER //

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

    INSERT INTO block_audit_log (action, username, client_ip, client_port, reason, operator)
    VALUES ('block', p_username, p_client_ip, p_client_port, p_reason, p_operator);
END //

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
END //

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

-- ============ 5.5+ 方案：自动解封事件 ============
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
SQL_55
    then ok "5.5+ 方案对象创建完成"
    else fail "5.5+ 方案对象创建失败，请检查上方错误输出"; rec_fail "部署核心对象"; exit 1; fi
fi
rec_ok "部署核心对象"

# 验证核心表确实创建成功（防止 mysql 批处理模式静默失败导致步骤 4 误判 ok）
BLK_CHECK=$(mysql_run -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='security' AND table_name='client_blacklist';" 2>/dev/null)
if [ "$BLK_CHECK" != "1" ]; then
    fail "核心表 security.client_blacklist 未创建成功（步骤 4 可能静默失败），终止部署"
    rec_fail "部署核心对象（表缺失 security.client_blacklist）"
    exit 1
fi

# =====================================================================
# 步骤 5: 自动授权普通用户（先授权，后开 init_connect！）
# =====================================================================
echo ""
echo "==> [5/8] 自动授权普通用户"

EXCLUDE_USERS="'root','debian-sys-maint','mysql','mysql.sys','mysql.session','mysql.infoschema','mysqlx','mysqlx.sys','repl'"

USER_LIST=$(mysql_run -e "
SELECT CONCAT(QUOTE(User), ',', QUOTE(Host))
FROM mysql.user
WHERE Super_priv = 'N'
  AND User != ''
  AND User NOT IN ($EXCLUDE_USERS)
ORDER BY User, Host" 2>/dev/null)

if [ -z "$USER_LIST" ]; then
    warn "未发现需要授权的普通用户，跳过授权步骤"
    rec_ok "自动授权（无用户需授权）"
else
    GRANT_CNT=0
    FAIL_CNT=0
    echo "  以下账号将获得阻断检查权限："
    while IFS= read -r line; do
        u="${line%%,*}"; h="${line##*,}"
        u="${u//\'/}"; h="${h//\'/}"
        if [ -z "$u" ]; then
            continue
        fi
        if [ "$SCHEME" = "51" ]; then
            GSQL="GRANT EXECUTE ON PROCEDURE security.check_blacklist_51 TO '$u'@'$h';"
        else
            GSQL="GRANT SELECT ON security.client_blacklist TO '$u'@'$h';"
        fi
        echo "      GRANT: '$u'@'$h'"
        echo "        -> $GSQL"
        if ERR_MSG=$(mysql_run -e "$GSQL" 2>&1); then
            GRANT_CNT=$((GRANT_CNT+1))
        else
            FAIL_CNT=$((FAIL_CNT+1))
            fail "授权失败: '$u'@'$h' -> $(echo "$ERR_MSG" | tail -1)"
        fi
    done <<< "$USER_LIST"
    mysql_run -e "FLUSH PRIVILEGES" >/dev/null 2>&1
    if [ "$FAIL_CNT" -gt 0 ]; then
        fail "授权完成：成功 $GRANT_CNT 个，失败 $FAIL_CNT 个"
        rec_fail "自动授权（$FAIL_CNT 个失败）"
    else
        ok "授权完成：成功 $GRANT_CNT 个账号（授权 SQL 已打印如上）"
        rec_ok "自动授权（$GRANT_CNT 个账号）"
    fi
fi

# =====================================================================
# 步骤 6: 开启阻断（设置 init_connect）——总开关，最后执行
# =====================================================================
echo ""
echo "==> [6/8] 开启阻断（设置 init_connect）"
if [ "$SCHEME" = "51" ]; then
    if mysql_run -e "SET GLOBAL init_connect = 'CALL security.check_blacklist_51();';" >/dev/null 2>&1; then
        ok "init_connect 已设置: CALL security.check_blacklist_51();"
    else
        fail "设置 init_connect 失败"; rec_fail "开启阻断"; exit 1
    fi
else
    if mysql_run <<'SQL'
SET GLOBAL init_connect = "SELECT CASE WHEN EXISTS(SELECT 1 FROM security.client_blacklist WHERE username = SUBSTRING_INDEX(USER(),'@',1) AND client_ip = SUBSTRING_INDEX(USER(),'@',-1) AND status = 'active' AND (expire_at IS NULL OR expire_at > NOW())) THEN EXP(710) ELSE 1 END";
SQL
    then
        ok "init_connect 已设置: SELECT CASE WHEN ... THEN EXP(710) ELSE 1 END"
    else
        fail "设置 init_connect 失败"; rec_fail "开启阻断"; exit 1
    fi
fi
rec_ok "开启阻断"

# =====================================================================
# 步骤 7: my.cnf 持久化（询问用户）
# =====================================================================
echo ""
echo "==> [7/8] my.cnf 持久化"
echo "  提示: init_connect 为动态配置，MySQL 重启后失效，建议写入 my.cnf"
read -r -t 30 -p "  是否自动写入 my.cnf 持久化配置？[y/N] " PERSIST
PERSIST="${PERSIST:-N}"
if [[ "$PERSIST" =~ ^[Yy]$ ]]; then
    MYCNF=""
    for f in /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf "$HOME/.my.cnf"; do
        if [ -f "$f" ] && [ -w "$f" ]; then MYCNF="$f"; break; fi
    done
    if [ -z "$MYCNF" ] && command -v mysqld >/dev/null 2>&1; then
        MYCNF=$(mysqld --verbose --help 2>/dev/null | sed -n 's/^Default options are read from the following files in the given order: //p' | tr ' ' '\n' | grep -v '^$' | head -1)
        if [ -n "$MYCNF" ] && [ ! -f "$MYCNF" ]; then MYCNF=""; fi
        if [ -n "$MYCNF" ] && [ ! -w "$MYCNF" ]; then MYCNF=""; fi
    fi
    if [ -z "$MYCNF" ]; then
        warn "未找到可写的 my.cnf，请手动配置（配置片段见下方汇总）"
        rec_ok "my.cnf 持久化（手动配置）"
    else
        BK="${MYCNF}.bak.$(date +%Y%m%d%H%M%S)"
        cp "$MYCNF" "$BK"
        if grep -q '^init_connect' "$MYCNF"; then
            warn "my.cnf 已存在 init_connect 配置，未重复写入（原文件已备份: $BK）"
        else
            BLOCK_FILE="$(mktemp)"
            if [ "$SCHEME" = "51" ]; then
                cat > "$BLOCK_FILE" <<'EOF'
# MySQL 软阻断系统（自动写入）
init_connect='CALL security.check_blacklist_51();'
event_scheduler=ON
EOF
            else
                cat > "$BLOCK_FILE" <<'EOF'
# MySQL 软阻断系统（自动写入）
init_connect='SELECT CASE WHEN EXISTS(SELECT 1 FROM security.client_blacklist WHERE username = SUBSTRING_INDEX(USER(),''@'',1) AND client_ip = SUBSTRING_INDEX(USER(),''@'',-1) AND status = ''active'' AND (expire_at IS NULL OR expire_at > NOW())) THEN EXP(710) ELSE 1 END'
event_scheduler=ON
EOF
            fi
            # 参数必须写入 [mysqld] 段内，否则 mysqld 不会读取
            if grep -q '^\[mysqld\]' "$MYCNF"; then
                # 已有 [mysqld] 段：插入到段头之后（避免落入其后的其他段落）
                LN=$(grep -n '^\[mysqld\]' "$MYCNF" | head -1 | cut -d: -f1)
                TMP_MYCNF="$(mktemp)"
                head -n "$LN" "$MYCNF" > "$TMP_MYCNF"
                cat "$BLOCK_FILE" >> "$TMP_MYCNF"
                tail -n "+$((LN + 1))" "$MYCNF" >> "$TMP_MYCNF"
                cat "$TMP_MYCNF" > "$MYCNF"
                rm -f "$TMP_MYCNF"
            else
                # 无 [mysqld] 段：文件末尾追加
                echo "" >> "$MYCNF"
                echo "[mysqld]" >> "$MYCNF"
                cat "$BLOCK_FILE" >> "$MYCNF"
            fi
            rm -f "$BLOCK_FILE"
            ok "已写入 $MYCNF（参数位于 [mysqld] 段内，原文件备份: $BK）"
        fi
        rec_ok "my.cnf 持久化（写入 $MYCNF）"
    fi
else
    info "跳过 my.cnf 持久化（重启后需手动配置，配置片段见下方汇总）"
    rec_ok "my.cnf 持久化（跳过）"
fi

# =====================================================================
# 步骤 8: 部署验证
# =====================================================================
echo ""
echo "==> [8/8] 部署验证"
VFAIL=0

TBL=$(mysql_run -e "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='security' ORDER BY TABLE_NAME" 2>/dev/null)
if [ "$SCHEME" = "51" ]; then
    for t in client_blacklist block_audit_log block_trigger; do
        echo "$TBL" | grep -qx "$t" && ok "表 security.$t 存在" || { fail "表 security.$t 缺失"; VFAIL=1; }
    done
else
    for t in client_blacklist block_audit_log; do
        echo "$TBL" | grep -qx "$t" && ok "表 security.$t 存在" || { fail "表 security.$t 缺失"; VFAIL=1; }
    done
fi

PROCS=$(mysql_run -e "SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='security' AND ROUTINE_TYPE='PROCEDURE' ORDER BY ROUTINE_NAME" 2>/dev/null)
for p in sp_block_client sp_unblock_client sp_show_blacklist sp_show_audit_log; do
    echo "$PROCS" | grep -qx "$p" && ok "存储过程 security.$p 存在" || { fail "存储过程 security.$p 缺失"; VFAIL=1; }
done
if [ "$SCHEME" = "51" ]; then
    echo "$PROCS" | grep -qx "check_blacklist_51" && ok "存储过程 security.check_blacklist_51 存在" || { fail "存储过程 check_blacklist_51 缺失"; VFAIL=1; }
fi

EV=$(mysql_run -e "SELECT EVENT_NAME FROM information_schema.EVENTS WHERE EVENT_SCHEMA='security' AND EVENT_NAME='ev_auto_release_blacklist'" 2>/dev/null)
[ -n "$EV" ] && ok "事件 ev_auto_release_blacklist 存在" || { fail "事件 ev_auto_release_blacklist 缺失"; VFAIL=1; }

INIT=$(mysql_run -e "SELECT @@global.init_connect" 2>/dev/null)
[ -n "$INIT" ] && [ "$INIT" != "NULL" ] && ok "init_connect 已配置" || { fail "init_connect 未配置"; VFAIL=1; }

ES=$(mysql_run -e "SELECT @@global.event_scheduler" 2>/dev/null)
[ "$ES" = "ON" ] && ok "事件调度器已开启 (event_scheduler=ON)" || warn "事件调度器状态: ${ES:-未知}"

if [ -n "${USER_LIST:-}" ]; then
    FIRST_U="${USER_LIST%%$'\n'*}"
    fu="${FIRST_U%%,*}"; fh="${FIRST_U##*,}"
    fu="${fu//\'/}"; fh="${fh//\'/}"
    G=$(mysql_run -e "SHOW GRANTS FOR '$fu'@'$fh'" 2>/dev/null | grep -i 'client_blacklist\|check_blacklist_51')
    if [ -n "$G" ]; then
        ok "抽查授权: '$fu'@'$fh' 权限正常"
    else
        warn "抽查授权: '$fu'@'$fh' 未见阻断权限（可能非业务账号，可手动核查）"
    fi
fi

if [ "$VFAIL" -eq 0 ]; then rec_ok "部署验证"; else rec_fail "部署验证"; fi

# =====================================================================
# 汇总
# =====================================================================
echo ""
echo "============================================================"
echo " MySQL 软阻断部署结果汇总"
echo "============================================================"
for r in "${RESULTS[@]}"; do
    st="${r%%|*}"; msg="${r#*|}"
    if [ "$st" = "OK" ]; then echo -e "  ${GREEN}[OK]${NC}   $msg"; else echo -e "  ${RED}[FAIL]${NC} $msg"; fi
done
echo "------------------------------------------------------------"
echo "  方案: ${SCHEME}  |  版本: ${VERSION_STR}"
echo ""
echo "后续操作:"
echo "  1. 测试封禁:  CALL security.sp_block_client('测试用户','IP',NULL,'测试封禁','dba',1);"
echo "  2. 验证阻断:  用该用户连接，预期收到 ERROR 1184 (init_connect command failed)"
echo "  3. 解封:      CALL security.sp_unblock_client('测试用户','IP','dba');"
echo "  4. 查看黑名单: CALL security.sp_show_blacklist();"
echo "  5. my.cnf 手动持久化片段（如跳过自动写入）:"
if [ "$SCHEME" = "51" ]; then
    echo "     [mysqld]"
    echo "     init_connect='CALL security.check_blacklist_51();'"
else
    echo "     [mysqld]"
    echo "     init_connect='SELECT CASE WHEN EXISTS(SELECT 1 FROM security.client_blacklist WHERE username = SUBSTRING_INDEX(USER(),''@'',1) AND client_ip = SUBSTRING_INDEX(USER(),''@'',-1) AND status = ''active'' AND (expire_at IS NULL OR expire_at > NOW())) THEN EXP(710) ELSE 1 END'"
fi
echo "     event_scheduler=ON"
echo "  6. 如个别账号无需阻断检查权限，可手动 REVOKE 回收"
echo "============================================================"
