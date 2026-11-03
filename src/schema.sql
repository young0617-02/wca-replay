-- worktime-compliance-agent · schema v1（SQLite / PostgreSQL 18 共用）
-- 设计约束：
--   1) 金额一律以「分」整数存储，工时一律以「分钟」整数存储，禁止浮点参与判定。
--   2) 每一条业务事实都带 (source_file_id, source_line_no)，行级可追溯（A7）。
--   3) 结论(finding)与运行(run)分离，run 携带「规则版本 + 输入指纹 + 结论摘要」三元组（F-007）。
--   4) 知识库条目带出处 / 生效日期 / 地域 / 版本 / ACL 谓词（F-008、F-009）。
--   5) 审计日志为 hash 链，前一条哈希入库，篡改即可检出（F-007）。
--
-- 方言边界：本文件不写连接级开关；PostgreSQL 的自增列由 src/db.py 在初始化时翻译。
-- 连接级设置（foreign_keys / WAL / synchronous / busy_timeout）只属于 SQLite 连接路径。

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ---------------------------------------------------------------- 文件与行级溯源
CREATE TABLE IF NOT EXISTS raw_file (
    file_id        INTEGER PRIMARY KEY,
    rel_path       TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('org','punch','leave','trip','correction','schedule','employee')),
    row_count      INTEGER NOT NULL,
    header_sha256  TEXT NOT NULL,
    imported_at    TEXT NOT NULL,
    UNIQUE (sha256, rel_path)
);

CREATE TABLE IF NOT EXISTS ingest_issue (
    issue_id    INTEGER PRIMARY KEY,
    file_id     INTEGER NOT NULL REFERENCES raw_file(file_id) ON DELETE CASCADE,
    line_no     INTEGER NOT NULL,
    rule_id     TEXT NOT NULL,
    emp_id      TEXT NOT NULL DEFAULT '',   -- O-2：导入期尽力归属，让脏数据能进复核队列
    work_date   TEXT NOT NULL DEFAULT '',   -- 可解析时记录归属工作日，便于按天聚合
    severity    TEXT NOT NULL CHECK (severity IN ('DEFENSIBLE','REVIEW','VIOLATION','REJECT')),
    field_name  TEXT,
    raw_value   TEXT,
    detail      TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ingest_issue_file ON ingest_issue(file_id, line_no);

-- ---------------------------------------------------------------- 组织 / 员工 / 权限
CREATE TABLE IF NOT EXISTS org_unit (
    org_id     TEXT PRIMARY KEY,
    org_name   TEXT NOT NULL,
    parent_id  TEXT,
    org_path   TEXT NOT NULL DEFAULT '',   -- Phase 7 P0：物化层级路径 /ROOT/CHILD/
    org_level  INTEGER NOT NULL DEFAULT 0  -- 根为 0，逐级 +1
);

CREATE TABLE IF NOT EXISTS employee (
    emp_id                 TEXT PRIMARY KEY,
    pseudonym              TEXT NOT NULL,          -- 合成化名，绝不存真实姓名
    job_code               TEXT NOT NULL DEFAULT 'unknown',  -- 岗位编码，决定特殊工时适用性（503号文4/5条）
    org_id                 TEXT NOT NULL REFERENCES org_unit(org_id),
    region_code            TEXT NOT NULL,
    worktime_regime        TEXT NOT NULL CHECK (worktime_regime IN
                            ('standard','comprehensive_monthly','comprehensive_quarterly',
                             'comprehensive_yearly','flexible')),
    contract_approved_flex INTEGER NOT NULL DEFAULT 0,  -- 不定时/综合工时是否取得审批（503号文要求）
    pay_base_cents         INTEGER NOT NULL,       -- 加班工资计算基数（分/小时），见 pay_base_source
    pay_base_hourly_cents  INTEGER NOT NULL,
    normal_hourly_cents    INTEGER NOT NULL,       -- 正常工作时间小时工资（分）
    is_manager             INTEGER NOT NULL DEFAULT 0,
    acl_scope              TEXT NOT NULL DEFAULT 'self' CHECK (acl_scope IN ('self','own_org','public'))
);

-- ---------------------------------------------------------------- 事实表
-- 特殊工时审批台账（v5 REG-01 的最小证据表）。
-- 只登记“能核验”的字段：文号、期限、岗位范围、城市、附件哈希；
-- 没有行 = 未覆盖，不拿 employee.contract_approved_flex 反推审批文号。
CREATE TABLE IF NOT EXISTS worktime_approval (
    approval_id       INTEGER PRIMARY KEY,
    emp_id            TEXT NOT NULL REFERENCES employee(emp_id) ON DELETE CASCADE,
    doc_no            TEXT NOT NULL,
    regime            TEXT NOT NULL CHECK (regime IN
                          ('comprehensive_monthly','comprehensive_quarterly',
                           'comprehensive_yearly','flexible')),
    valid_from        TEXT NOT NULL,
    valid_to          TEXT NOT NULL,
    job_codes         TEXT NOT NULL DEFAULT '[]',    -- JSON list；空列表视为未登记岗位范围
    region_code       TEXT NOT NULL DEFAULT '',
    attachment_sha256 TEXT NOT NULL DEFAULT '',
    recorded_at       TEXT NOT NULL,
    UNIQUE (emp_id, doc_no)
);
CREATE INDEX IF NOT EXISTS idx_approval_emp ON worktime_approval(emp_id, regime);

-- ------------------------------------------------ 审批台账 P0：批文 / 版本 / 范围 / 覆盖投影
-- 批文主表只保存文号级元数据；版本不可覆盖，发布后才生成员工覆盖投影。
-- 附件只登记 sha256，不保存原件，不存文件路径/BLOB。
CREATE TABLE IF NOT EXISTS approval_doc (
    doc_id          INTEGER PRIMARY KEY,
    doc_no          TEXT NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    issuer          TEXT NOT NULL,
    regime          TEXT NOT NULL CHECK (regime IN
                        ('comprehensive_monthly','comprehensive_quarterly',
                         'comprehensive_yearly','flexible')),
    status          TEXT NOT NULL DEFAULT 'DRAFT'
                        CHECK (status IN ('DRAFT','PUBLISHED','RETIRED')),
    current_version INTEGER,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    updated_by      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_doc_version (
    version_id        INTEGER PRIMARY KEY,
    doc_id            INTEGER NOT NULL REFERENCES approval_doc(doc_id) ON DELETE CASCADE,
    version_no        INTEGER NOT NULL,
    valid_from        TEXT NOT NULL,
    valid_to          TEXT NOT NULL,
    job_codes         TEXT NOT NULL,
    region_code       TEXT NOT NULL,
    attachment_sha256 TEXT NOT NULL,
    change_note       TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'DRAFT'
                          CHECK (status IN ('DRAFT','PUBLISHED','SUPERSEDED')),
    published_at      TEXT,
    published_by      TEXT,
    created_at        TEXT NOT NULL,
    created_by        TEXT NOT NULL,
    UNIQUE (doc_id, version_no)
);
CREATE INDEX IF NOT EXISTS idx_approval_doc_version_doc ON approval_doc_version(doc_id, version_no);

CREATE TABLE IF NOT EXISTS approval_doc_scope (
    scope_id    INTEGER PRIMARY KEY,
    version_id  INTEGER NOT NULL REFERENCES approval_doc_version(version_id) ON DELETE CASCADE,
    scope_type  TEXT NOT NULL CHECK (scope_type IN ('org','employee')),
    scope_value TEXT NOT NULL,
    UNIQUE (version_id, scope_type, scope_value)
);

CREATE TABLE IF NOT EXISTS employee_approval_coverage (
    coverage_id       INTEGER PRIMARY KEY,
    emp_id            TEXT NOT NULL,
    doc_id            INTEGER NOT NULL REFERENCES approval_doc(doc_id) ON DELETE CASCADE,
    version_id        INTEGER NOT NULL REFERENCES approval_doc_version(version_id) ON DELETE CASCADE,
    doc_no            TEXT NOT NULL,
    version_no        INTEGER NOT NULL,
    regime            TEXT NOT NULL,
    valid_from        TEXT NOT NULL,
    valid_to          TEXT NOT NULL,
    job_codes         TEXT NOT NULL,
    region_code       TEXT NOT NULL,
    attachment_sha256 TEXT NOT NULL,
    published_at      TEXT NOT NULL,
    UNIQUE (emp_id, doc_id, version_id)
);
CREATE INDEX IF NOT EXISTS idx_coverage_emp ON employee_approval_coverage(emp_id, regime, valid_from, valid_to);

CREATE TABLE IF NOT EXISTS punch (
    punch_id        INTEGER PRIMARY KEY,
    emp_id          TEXT NOT NULL,
    event_ts        TEXT NOT NULL,   -- ISO-8601 +08:00，规范化后
    event_minute    INTEGER NOT NULL,-- 相对 day_anchor 的分钟偏移，跨天为负/超 1440
    day_anchor      TEXT NOT NULL,   -- 归属工作日 YYYY-MM-DD
    device_id       TEXT,
    punch_type      TEXT NOT NULL CHECK (punch_type IN ('in','out','unknown')),
    raw_text        TEXT NOT NULL,
    source_file_id  INTEGER REFERENCES raw_file(file_id),
    source_line_no  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_punch_emp_day ON punch(emp_id, day_anchor);
CREATE INDEX IF NOT EXISTS idx_ingest_issue_emp ON ingest_issue(emp_id, work_date);

-- O-3：打卡事实按内容唯一，而不是按「来自哪个文件」唯一。
-- 同一批数据换个文件名重传不再二次入账（旧的幂等键只认 rel_path+sha256，改名即重复）。
CREATE UNIQUE INDEX IF NOT EXISTS idx_punch_dedup ON punch(emp_id, event_ts, punch_type,
                                                           COALESCE(device_id, ''));

CREATE TABLE IF NOT EXISTS shift_plan (
    shift_id        INTEGER PRIMARY KEY,
    emp_id          TEXT NOT NULL,
    work_date       TEXT NOT NULL,
    planned_start   TEXT NOT NULL,
    planned_end     TEXT NOT NULL,
    crosses_midnight INTEGER NOT NULL DEFAULT 0,
    rest_minutes    INTEGER NOT NULL DEFAULT 0,
    source_file_id  INTEGER REFERENCES raw_file(file_id),
    source_line_no  INTEGER,
    UNIQUE (emp_id, work_date)
);

CREATE TABLE IF NOT EXISTS leave_record (
    leave_id        INTEGER PRIMARY KEY,
    emp_id          TEXT NOT NULL,
    leave_kind      TEXT NOT NULL,
    start_ts        TEXT NOT NULL,
    end_ts          TEXT NOT NULL,
    approved        INTEGER NOT NULL DEFAULT 1,
    paid            INTEGER NOT NULL DEFAULT 1,
    source_file_id  INTEGER REFERENCES raw_file(file_id),
    source_line_no  INTEGER
);

CREATE TABLE IF NOT EXISTS trip_record (
    trip_id         INTEGER PRIMARY KEY,
    emp_id          TEXT NOT NULL,
    destination     TEXT NOT NULL,
    start_ts        TEXT NOT NULL,
    end_ts          TEXT NOT NULL,
    source_file_id  INTEGER REFERENCES raw_file(file_id),
    source_line_no  INTEGER
);

CREATE TABLE IF NOT EXISTS punch_correction (
    correction_id   INTEGER PRIMARY KEY,
    emp_id          TEXT NOT NULL,
    claimed_ts      TEXT NOT NULL,
    claimed_type    TEXT NOT NULL CHECK (claimed_type IN ('in','out')),
    reason          TEXT NOT NULL,
    approved        INTEGER NOT NULL DEFAULT 0,
    source_file_id  INTEGER REFERENCES raw_file(file_id),
    source_line_no  INTEGER
);

-- ---------------------------------------------------------------- 派生：工作日汇总（确定性）
CREATE TABLE IF NOT EXISTS attendance_day (
    emp_id                 TEXT NOT NULL,
    work_date              TEXT NOT NULL,
    day_type               TEXT NOT NULL CHECK (day_type IN
                            ('workday','rest_day_swap','statutory_holiday','plain_rest_day','unknown')),
    minutes_worked         INTEGER NOT NULL DEFAULT 0,
    minutes_ot_weekday     INTEGER NOT NULL DEFAULT 0,
    minutes_ot_restday     INTEGER NOT NULL DEFAULT 0,
    minutes_ot_holiday     INTEGER NOT NULL DEFAULT 0,
    minutes_night          INTEGER NOT NULL DEFAULT 0,
    minutes_rest           INTEGER NOT NULL DEFAULT 0,
    crossed_midnight       INTEGER NOT NULL DEFAULT 0,
    first_punch            TEXT,
    last_punch             TEXT,
    punch_count            INTEGER NOT NULL DEFAULT 0,
    source_refs            TEXT NOT NULL DEFAULT '[]',   -- JSON: [{"file_id":..,"line_no":..}]
    PRIMARY KEY (emp_id, work_date)
);

-- ---------------------------------------------------------------- 结论 / 运行 / 审计
CREATE TABLE IF NOT EXISTS run (
    run_id              TEXT PRIMARY KEY,
    started_at          TEXT NOT NULL,
    finished_at         TEXT,
    engine_version      TEXT NOT NULL,
    rule_pack_version   TEXT NOT NULL,
    input_fingerprint   TEXT NOT NULL,
    conclusion_digest   TEXT,
    scope_json          TEXT NOT NULL,
    notes               TEXT,
    -- 本次校验**真正引用到**的输入文件 id（JSON 数组，升序）。
    -- 存在这里是为了让举证包能自含输入并支持外部重放；不进 scope，因此不影响输入指纹。
    referenced_file_ids TEXT
);

CREATE TABLE IF NOT EXISTS finding (
    finding_id         INTEGER PRIMARY KEY,
    run_id             TEXT NOT NULL REFERENCES run(run_id) ON DELETE CASCADE,
    rule_id            TEXT NOT NULL,
    rule_version       TEXT NOT NULL,
    emp_id             TEXT NOT NULL,
    work_date          TEXT,
    period_key         TEXT,
    severity           TEXT NOT NULL CHECK (severity IN ('DEFENSIBLE','REVIEW','VIOLATION')),
    metric_json        TEXT NOT NULL,   -- 全部整数分/分钟；确定性计算结果
    citation_ids       TEXT NOT NULL,   -- JSON list of kb_doc.doc_id
    source_refs        TEXT NOT NULL,   -- JSON list of {"file_id","line_no"}
    explanation        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_run ON finding(run_id, rule_id, emp_id, work_date);

CREATE TABLE IF NOT EXISTS audit_event (
    seq            INTEGER PRIMARY KEY,
    run_id         TEXT,
    actor          TEXT NOT NULL,
    action         TEXT NOT NULL,
    ts             TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    entry_hash     TEXT NOT NULL,
    rule_pack_version TEXT,          -- NULL = v4 legacy 事件；v5 事件为 v5
    segment_id     TEXT              -- NULL = legacy 段；v5 指向 rule_pack_epoch
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_entry_hash ON audit_event(entry_hash);
CREATE INDEX IF NOT EXISTS idx_audit_segment ON audit_event(segment_id, seq);

-- 规则包纪元：旧链头、切换事件、新段起点。审计链只追加，不重置旧 genesis。
CREATE TABLE IF NOT EXISTS rule_pack_epoch (
    epoch_id             TEXT PRIMARY KEY,
    rule_pack_version    TEXT NOT NULL,
    prev_rule_pack_version TEXT NOT NULL,
    prev_head_hash       TEXT NOT NULL,
    activation_event_seq INTEGER NOT NULL,
    segment_start_seq    INTEGER NOT NULL,
    segment_start_prev_hash TEXT NOT NULL,
    switched_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_epoch_pack ON rule_pack_epoch(rule_pack_version, activation_event_seq);

CREATE TABLE IF NOT EXISTS evidence_package (
    package_id         TEXT PRIMARY KEY,
    run_id             TEXT NOT NULL REFERENCES run(run_id),
    created_at         TEXT NOT NULL,
    rule_pack_version  TEXT NOT NULL,
    input_fingerprint  TEXT NOT NULL,
    conclusion_digest  TEXT NOT NULL,
    manifest_sha256    TEXT NOT NULL,
    package_dir        TEXT NOT NULL,
    row_count          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS review_item (
    review_id    INTEGER PRIMARY KEY,
    run_id       TEXT,
    source_type  TEXT NOT NULL CHECK (source_type IN ('finding','answer','ingest_issue')),
    source_id    TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','APPROVED','REJECTED','NEEDS_MORE_DATA')),
    reviewer     TEXT,
    decided_at   TEXT,
    note         TEXT
);
CREATE INDEX IF NOT EXISTS idx_review_status ON review_item(status, source_type);

-- ---------------------------------------------------------------- 知识库（F-008）
CREATE TABLE IF NOT EXISTS kb_doc (
    doc_id            TEXT PRIMARY KEY,
    doc_type          TEXT NOT NULL CHECK (doc_type IN
                       ('law','administrative_regulation','department_rule','local_regulation',
                        'holiday_notice','internal_policy','personnel_data','faq')),
    title             TEXT NOT NULL,
    category          TEXT NOT NULL DEFAULT '',    -- personnel_data 的细分类：attendance_summary / payroll_detail
    article_no        TEXT NOT NULL DEFAULT '',
    body              TEXT NOT NULL,
    source_citation   TEXT NOT NULL,      -- 可直接点开的出处（法规名+条号 / 文号 / 本地文件）
    source_url        TEXT NOT NULL DEFAULT '',
    issuing_authority TEXT NOT NULL DEFAULT '',
    doc_no            TEXT NOT NULL DEFAULT '',
    effective_from    TEXT NOT NULL DEFAULT '',
    effective_to      TEXT NOT NULL DEFAULT '',
    region_code       TEXT NOT NULL DEFAULT 'CN',
    version           TEXT NOT NULL,
    acl_scope         TEXT NOT NULL CHECK (acl_scope IN ('public','own_org','own_org_manager','self')),
    acl_org_ids       TEXT NOT NULL DEFAULT '[]',   -- JSON list
    acl_emp_id        TEXT NOT NULL DEFAULT '',     -- personnel_data 归属人
    confidence_note   TEXT NOT NULL DEFAULT '',     -- 确信度：高 / 中 / 待核对
    body_sha256       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kb_doc_acl ON kb_doc(acl_scope, region_code);

CREATE TABLE IF NOT EXISTS kb_term (
    term    TEXT NOT NULL,
    doc_id  TEXT NOT NULL REFERENCES kb_doc(doc_id) ON DELETE CASCADE,
    tf      INTEGER NOT NULL,
    PRIMARY KEY (term, doc_id)
);
CREATE INDEX IF NOT EXISTS idx_kb_term_term ON kb_term(term);

-- ACL 归属组织规范化表：权限谓词靠 JOIN 下推到检索层，不依赖 JSON 函数是否编译进来
CREATE TABLE IF NOT EXISTS kb_doc_org (
    doc_id  TEXT NOT NULL REFERENCES kb_doc(doc_id) ON DELETE CASCADE,
    org_id  TEXT NOT NULL,
    PRIMARY KEY (doc_id, org_id)
);
CREATE INDEX IF NOT EXISTS idx_kb_doc_org ON kb_doc_org(org_id);

CREATE TABLE IF NOT EXISTS kb_link (
    from_doc  TEXT NOT NULL REFERENCES kb_doc(doc_id) ON DELETE CASCADE,
    to_doc    TEXT NOT NULL REFERENCES kb_doc(doc_id) ON DELETE CASCADE,
    link_kind TEXT NOT NULL DEFAULT 'implements',
    PRIMARY KEY (from_doc, to_doc, link_kind)
);

-- ---------------------------------------------------------------- 问答与可观测（F-010 / F-013）
CREATE TABLE IF NOT EXISTS question_log (
    qid                 TEXT PRIMARY KEY,
    asked_at            TEXT NOT NULL,
    actor_emp_id        TEXT NOT NULL,
    question            TEXT NOT NULL,
    intent              TEXT NOT NULL,
    tier                TEXT NOT NULL DEFAULT 'unknown',
    answer              TEXT NOT NULL,
    confidence_permille INTEGER NOT NULL,
    evidence_coverage_permille INTEGER NOT NULL,
    gate_decision       TEXT NOT NULL CHECK (gate_decision IN
                         ('ANSWERED','EXPLAIN_ONLY','REFUSED_ACL','REFUSED_NO_EVIDENCE','ESCALATED')),
    needs_review        INTEGER NOT NULL DEFAULT 0,
    citation_ids        TEXT NOT NULL,
    numeric_tokens      TEXT NOT NULL DEFAULT '[]',
    allowed_numbers     TEXT NOT NULL DEFAULT '[]',
    provider            TEXT NOT NULL,
    model               TEXT NOT NULL,
    tokens_in_est       INTEGER NOT NULL DEFAULT 0,
    tokens_out_est      INTEGER NOT NULL DEFAULT 0,
    tool_calls_json     TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS span (
    span_id      INTEGER PRIMARY KEY,
    qid          TEXT NOT NULL,
    segment      TEXT NOT NULL,   -- plan / retrieve / tool_numeric / assemble / total
    duration_us  INTEGER NOT NULL,
    extra_json   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_span_qid ON span(qid, segment);

CREATE TABLE IF NOT EXISTS eval_result (
    eval_id    INTEGER PRIMARY KEY,
    run_label  TEXT NOT NULL,
    item_id    TEXT NOT NULL,
    tier       TEXT NOT NULL,
    metric     TEXT NOT NULL,
    passed     INTEGER NOT NULL,
    observed   TEXT NOT NULL,
    expected   TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT ''
);

-- ---------------------------------------------------------------- 界面身份与会话（US-UI-05 / NFR-15 / NFR-16）
-- 口令只存 scrypt 哈希；令牌只存 sha256，明文令牌既不落库也不落日志。
CREATE TABLE IF NOT EXISTS app_user (
    user_id    INTEGER PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE,
    emp_id     TEXT NOT NULL REFERENCES employee(emp_id),
    roles      TEXT NOT NULL,             -- JSON 数组，取值 OP/RV/EM/AD
    pw_hash    TEXT NOT NULL CHECK (pw_hash LIKE 'scrypt$%'),
    algo       TEXT NOT NULL DEFAULT 'scrypt',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_session (
    token_hash   TEXT PRIMARY KEY,        -- sha256(会话令牌)
    username     TEXT NOT NULL REFERENCES app_user(username),
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_user ON app_session(username, expires_at);

-- 审批台账网页写操作的同步器 CSRF token：按会话 token_hash 绑定；退出/过期时删除。
CREATE TABLE IF NOT EXISTS app_csrf (
    token_hash  TEXT PRIMARY KEY,          -- sha256(会话令牌)
    csrf_hash   TEXT NOT NULL,             -- sha256(CSRF token)，不存明文
    created_at  TEXT NOT NULL
);
