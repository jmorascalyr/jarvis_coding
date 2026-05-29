-- ============================================================================
-- AWS CloudTrail Synthetic Scenario (Lua)
-- ============================================================================
-- Portable Lua clone of `Backend/event_generators/cloud_infrastructure/aws_cloudtrail.py`.
-- Produces a configurable burst of synthetic CloudTrail records that exercise
-- both benign corporate API calls and high-risk activity (Bedrock, SageMaker,
-- DynamoDB scans, KMS decrypts, etc.).
--
-- HEC routing is declared via `scenario.sources`; the sender layer will honor
-- the hint (`hec_path = "event"`) and pin the parser to `aws_cloudtrail-latest`.
-- ============================================================================

local scenario = {
  id          = "aws_cloudtrail_synthetic",
  name        = "AWS CloudTrail Synthetic Activity (Lua)",
  description = "Mixed benign + malicious CloudTrail audit traffic across IAM, S3, Bedrock, SageMaker, DynamoDB, KMS, and Secrets Manager. Lua port of the Python aws_cloudtrail generator.",
  version     = 1,

  -- Defaults consumed by the sender (per the lua-scenario-templating plan).
  -- The runner attaches these to every event emitted with this source; per-event
  -- `opts.hec_path` / `opts.parser` overrides still win when provided.
  sources = {
    aws_cloudtrail = {
      hec_path     = "event",                  -- structured JSON → /event
      parser       = "aws_cloudtrail-latest",  -- pin the sourcetype
      force_parser = false,
      format       = "json",
    },
  },

  mitre = {
    "T1078",       -- Valid Accounts
    "T1213",       -- Data from Information Repositories
    "T1530",       -- Data from Cloud Storage Object
    "T1552.005",   -- Cloud Instance Metadata API
    "T1059",       -- Command & Scripting Interpreter (Bedrock model abuse)
    "T1606.002",   -- Forge Web Credentials: SAML Tokens
  },

  iocs = {
    { type = "AWSAccount", value = "666666666666", meta = { role = "attacker account" } },
    { type = "IAMUser",    value = "suspicious.user", meta = { role = "attacker persona" } },
  },

  -- One actor + one host are enough for CloudTrail attribution headers.
  actors = {
    { id = "corp_users", role = "user",   name = "Corporate Workforce" },
    { id = "attacker",   role = "threat", name = "External Contractor", account = "666666666666" },
  },
  hosts = {
    { id = "control_plane", name = "aws-control-plane", os = "linux", type = "cloud" },
  },

  timing = {
    base = { mode = "now" },
    duration_minutes = 30,
    jitter_seconds = 5,
    phases = {
      normal_operations = { offset_minutes = 0 },
      suspicious_burst  = { offset_minutes = 15 },
    },
  },
}

-- ─────────────────────────── Static data pools ─────────────────────────────
local REGIONS = {
  "us-east-1", "us-west-2", "eu-central-1",
  "ap-southeast-2", "us-west-1", "eu-west-1",
}

local TLS_VERSIONS = { "TLSv1.2", "TLSv1.3" }
local CIPHERS = {
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES256-GCM-SHA384",
}

local USER_AGENTS = {
  "aws-cli/2.15.9 Python/3.11.4 Linux/5.10",
  "Corporate-Console/1.0 WebUI/2.4.7",
  "Business-SDK/3.2.1 CloudAPI/4.0",
  "aws-sdk-java/2.20.0 Linux/5.15 OpenJDK/17.0.6",
}

local CORPORATE_USERS = {
  { name = "john.smith",      role = "admin",          department = "it",            clearance = "high",   account = "123456789012" },
  { name = "jane.doe",        role = "manager",        department = "finance",       clearance = "medium", account = "123456789012" },
  { name = "bob.johnson",     role = "engineer",       department = "engineering",   clearance = "medium", account = "123456789012" },
  { name = "alice.williams",  role = "security-admin", department = "security",      clearance = "high",   account = "123456789012" },
  { name = "mike.davis",      role = "operator",       department = "operations",    clearance = "low",    account = "123456789012" },
  { name = "sarah.brown",     role = "doctor",         department = "medical",       clearance = "medium", account = "123456789012" },
  { name = "tom.wilson",      role = "analyst",        department = "analytics",     clearance = "low",    account = "123456789012" },
  { name = "lisa.taylor",     role = "director",       department = "executive",     clearance = "high",   account = "987654321098" },
  { name = "david.clark",     role = "scientist",      department = "research",      clearance = "high",   account = "987654321098" },
  { name = "karen.martinez",  role = "nurse",          department = "medical",       clearance = "medium", account = "987654321098" },
  { name = "steve.garcia",    role = "technician",     department = "maintenance",   clearance = "low",    account = "987654321098" },
  { name = "nancy.rodriguez", role = "coordinator",    department = "communications",clearance = "low",    account = "987654321098" },
  { name = "paul.lee",        role = "navigator",      department = "logistics",     clearance = "low",    account = "987654321098" },
  { name = "maria.gonzalez",  role = "pilot",          department = "transportation",clearance = "low",    account = "987654321098" },
  { name = "james.anderson",  role = "supervisor",     department = "operations",    clearance = "high",   account = "456789012345" },
  { name = "jennifer.thomas", role = "captain",        department = "leadership",    clearance = "high",   account = "567890123456" },
}

local ATTACKER_PERSONA = {
  name = "suspicious.user", role = "external-contractor",
  department = "unknown",   clearance = "unauthorized",
  account = "666666666666",
}

local CORPORATE_BUCKETS = {
  "company-logs-production", "application-telemetry-data",
  "confidential-documents", "research-academy-data",
  "datacenter-maintenance-logs", "backup-sensor-data",
  "analytics-charts", "security-analysis",
  "partner-zone-intel", "vendor-alliance-comms",
  "compliance-directive-files", "restricted-access",
  "hr-medical-records", "system-diagnostics",
  "training-program-library",
}

local NORMAL_APIS = {
  { "s3.amazonaws.com",             "PutObject" },
  { "s3.amazonaws.com",             "GetObject" },
  { "iam.amazonaws.com",            "CreateUser" },
  { "ec2.amazonaws.com",            "StartInstances" },
  { "ec2.amazonaws.com",            "DescribeInstances" },
  { "lambda.amazonaws.com",         "Invoke" },
  { "logs.amazonaws.com",           "CreateLogGroup" },
  { "athena.amazonaws.com",         "StartQueryExecution" },
  { "rds.amazonaws.com",            "CreateDBInstance" },
  { "cloudformation.amazonaws.com", "CreateStack" },
}

local MALICIOUS_APIS = {
  { "bedrock.amazonaws.com",         "CreateModel" },
  { "bedrock.amazonaws.com",         "CreateModelCustomizationJob" },
  { "sagemaker.amazonaws.com",       "CreateApp" },
  { "dynamodb.amazonaws.com",        "Scan" },
  { "dynamodb.amazonaws.com",        "BatchGetItem" },
  { "sts.amazonaws.com",             "AssumeRole" },
  { "guardduty.amazonaws.com",       "GetFindings" },
  { "secretsmanager.amazonaws.com",  "GetSecretValue" },
  { "kms.amazonaws.com",             "Decrypt" },
}

-- ─────────────────────────── Local helpers ─────────────────────────────────
local function pick(list)
  return list[math.random(1, #list)]
end

local function hex(n)
  local chars = "0123456789abcdef"
  local buf = {}
  for i = 1, n do
    local idx = math.random(1, 16)
    buf[i] = chars:sub(idx, idx)
  end
  return table.concat(buf)
end

local function upper_hex(n)
  return hex(n):upper()
end

local function fake_ipv4()
  return string.format("%d.%d.%d.%d",
    math.random(1, 223), math.random(0, 255),
    math.random(0, 255), math.random(0, 255))
end

local function safe_upper_token(value, length)
  local cleaned = (value or ""):upper():gsub("[^A-Z0-9]", "")
  if length and #cleaned > length then
    cleaned = cleaned:sub(1, length)
  end
  if #cleaned == 0 then cleaned = "USER" end
  return cleaned
end

-- API-specific request/response embellishments (mirrors `_get_api_extra`).
local function api_extras(api, story)
  local bucket = pick(CORPORATE_BUCKETS)
  if api == "PutObject" then
    return {
      requestParameters = {
        bucketName = bucket,
        key        = pick({
          "application-installer.exe",
          "financial-report.pdf",
          "security-protocol.bin",
          "user-activity-data.csv",
          "system-analysis.json",
        }),
        Host       = bucket .. ".s3.amazonaws.com",
        acl        = "private",
        encryption = "AES256",
      },
      additionalEventData = {
        bytesTransferredIn  = math.random(1024, 10485760),
        bytesTransferredOut = 0,
      },
    }
  elseif api == "GetObject" then
    return {
      requestParameters = {
        bucketName = bucket,
        key        = pick({
          "security-configs/firewall-rules.json",
          "analysis-reports/threat-assessment.xml",
          "user-manifests/employee-list.csv",
          "network-configs/security.dat",
          "access-logs/remote-users.log",
        }),
        Host       = bucket .. ".s3.amazonaws.com",
      },
    }
  elseif api == "StartQueryExecution" then
    return {
      requestParameters = {
        workGroup   = "corporate-analytics",
        queryString = pick({
          "SELECT * FROM security_events WHERE severity = 'high';",
          "SELECT * FROM user_sessions WHERE status = 'active';",
          "SELECT employee_id FROM users WHERE clearance = 'confidential';",
          "SELECT * FROM audit_logs WHERE timestamp > '2024-01-01';",
        }),
      },
    }
  elseif api == "GetFindings" then
    return {
      requestParameters = {
        detectorId = string.format("corporate-security-%s-%03d",
          pick({"prod", "stage", "dev"}), math.random(1, 999)),
        maxResults = math.random(5, 50),
      },
    }
  elseif api == "CreateModel" then
    return {
      requestParameters = {
        modelName     = pick({
          "threat-detection-ai", "security-analyzer",
          "behavioral-simulator", "compliance-monitoring-model",
        }),
        inferenceType = "EXTRACT_SECURITY_INSIGHTS",
      },
    }
  elseif api == "CreateModelCustomizationJob" then
    return {
      requestParameters = {
        baseModel         = "bedrock/corporate-llm",
        trainingDataS3Uri = string.format("s3://%s/classified/",
          pick({"restricted-access", "compliance-directive-files", "confidential-documents"})),
      },
    }
  elseif api == "CreateApp" then
    return {
      requestParameters = {
        appName         = pick({
          "data-analysis-portal", "business-intelligence-suite",
          "analytics-platform", "monitoring-dashboard",
        }),
        domainId        = string.format("d-%s-analytics-%03d",
          pick({"prod", "stage", "dev"}), math.random(1, 999)),
        userProfileName = pick({"data-analyst", "business-analyst", "security-analyst"}),
      },
    }
  elseif api == "Scan" then
    return {
      requestParameters = {
        tableName = pick({
          "CorporateClassifiedData", "SecurityDatabase",
          "SystemSpecifications", "ComplianceFiles",
        }),
        limit     = 1000000,
      },
      additionalEventData = {
        bytesTransferredOut = math.random(10000000, 100000000),
      },
    }
  elseif api == "BatchGetItem" then
    local table_name = pick({
      "CorporateSecurityDatabase", "BusinessAssetManifest",
      "ComplianceDirective", "FinancialProjectData",
    })
    local key_value = pick({"CONFIDENTIAL-DIRECTIVE", "BUSINESS-PROTOCOL", "SECURITY-ALPHA"})
    local requestItems = {}
    requestItems[table_name] = { Keys = { { id = { S = key_value } } } }
    return { requestParameters = { requestItems = requestItems } }
  elseif api == "GetSecretValue" then
    return {
      requestParameters = {
        secretId      = pick({
          "database-connection-strings", "api-access-tokens",
          "encryption-keys", "service-account-credentials", "ssl-certificates",
        }),
        versionStage  = "AWSCURRENT",
      },
    }
  elseif api == "Decrypt" then
    return {
      requestParameters = {
        ciphertextBlob = pick({
          "confidential-encrypted-files", "audit-investigations-data",
          "research-data", "system-blueprints",
        }),
        keyId          = "arn:aws:kms:us-east-1:corporate:key/" ..
          pick({"compliance-directive", "confidential-clearance", "security-operations"}),
      },
    }
  elseif api == "CreateUser" then
    return {
      requestParameters = {
        userName = pick({
          "intern.smith", "contractor.johnson",
          "manager.williams", "director.brown",
        }),
        tags = {
          { Key = "Office",     Value = pick({"NewYork", "LosAngeles", "Chicago", "Atlanta"}) },
          { Key = "Department", Value = pick({"Engineering", "Science", "Medical", "Management"}) },
        },
      },
    }
  elseif api == "AssumeRole" then
    return {
      requestParameters = {
        roleArn         = string.format("arn:aws:iam::%s:role/%s",
          pick({"123456789012", "987654321098"}),
          pick({"corporate-admin", "security-analyst", "compliance-auditor"})),
        roleSessionName = string.format("%s-session-%s",
          pick({"analysis", "monitoring", "audit"}), hex(8)),
        durationSeconds = pick({900, 1800, 3600}),
      },
    }
  end
  return nil
end

-- Build one CloudTrail record. `index` is 1-based for ordering; `phase_name`
-- is just used for the human-readable message.
local function build_event(story, index, force_malicious)
  local malicious = force_malicious
  if malicious == nil then
    malicious = math.random() < 0.30
  end

  local svc, api
  if malicious then
    local pair = pick(MALICIOUS_APIS)
    svc, api = pair[1], pair[2]
  else
    local pair = pick(NORMAL_APIS)
    svc, api = pair[1], pair[2]
  end

  local user = malicious and ATTACKER_PERSONA or pick(CORPORATE_USERS)
  local event_iso = story:at(0, index * 5)

  -- Build sessionContext.creationDate offset (5–60 min prior).
  local creation_minutes_back = math.random(5, 60)
  local creation_iso = story:at(-creation_minutes_back, index * 5)

  -- Expiration is 1h after eventTime.
  local expiration_iso = story:at(60, index * 5)

  local department_token = safe_upper_token(user.department, 12)
  local role_token       = safe_upper_token(user.role, 8)
  local vpce_token       = (user.department or "core"):gsub("[^a-z0-9]", "")
  if #vpce_token > 8 then vpce_token = vpce_token:sub(1, 8) end
  if #vpce_token == 0 then vpce_token = "core" end

  local record = {
    eventCategory      = malicious and "Insight" or pick({"Management", "Data", "Insight"}),
    eventName          = api,
    eventSource        = svc,
    eventTime          = event_iso,
    eventVersion       = "1.09",
    eventID            = story:uuid(),
    eventType          = "AwsApiCall",
    awsRegion          = pick(REGIONS),
    readOnly           = pick({true, false}),
    managementEvent    = true,
    recipientAccountId = user.account,
    sourceIPAddress    = fake_ipv4(),
    userAgent          = pick(USER_AGENTS),
    tlsDetails = {
      tlsVersion              = pick(TLS_VERSIONS),
      cipherSuite             = pick(CIPHERS),
      clientProvidedHostHeader = svc,
    },
    userIdentity = {
      type        = "IAMUser",
      principalId = string.format("AIDA%s%04d", department_token, math.random(1000, 9999)),
      arn         = string.format("arn:aws:iam::%s:user/%s", user.account, user.name),
      accountId   = user.account,
      accessKeyId = "AKIA" .. upper_hex(16),
      userName    = user.name,
      sessionContext = {
        sessionIssuer = {
          type        = "Role",
          principalId = "AROA" .. role_token,
          arn         = string.format("arn:aws:iam::%s:role/%s", user.account, user.role),
          userName    = user.role,
          accountId   = user.account,
        },
        attributes = {
          creationDate     = creation_iso,
          mfaAuthenticated = malicious and "false" or pick({"true", "false"}),
        },
      },
    },
    requestID = story:uuid(),
    requestParameters = {
      durationSeconds = 900,
      roleArn         = string.format("arn:aws:iam::%s:role/%s", user.account, user.role),
      roleSessionName = (user.department or "core") .. "-session",
      externalId      = story:uuid(),
    },
    responseElements = {
      assumedRoleUser = {
        assumedRoleId = string.format("AROA%s:%s-session", role_token, user.department or "core"),
        arn           = string.format("arn:aws:sts::%s:assumed-role/%s/%s-session",
          user.account, user.role, user.department or "core"),
      },
      credentials = {
        accessKeyId  = "ASIA" .. upper_hex(16),
        sessionToken = "IQoJb3JpZ2luX2VjEJ7//////////wEaCXVzLWVhc3QtMSJHMEUCIQD" .. hex(32),
        expiration   = expiration_iso,
      },
      sourceIdentity = user.name,
    },
    sharedEventID = story:uuid(),
    vpcEndpointId = string.format("vpce-%s-%s", vpce_token, hex(9)),
    resources = {
      {
        accountId = user.account,
        type      = "AWS::S3::Bucket",
        ARN       = "arn:aws:s3:::" .. pick(CORPORATE_BUCKETS),
      },
    },
    additionalEventData = {
      SignatureVersion     = "SigV4",
      CipherSuite          = pick(CIPHERS),
      bytesTransferredIn   = 0,
      bytesTransferredOut  = math.random(512, 10240),
      AuthenticationMethod = "AuthHeader",
      ["x-amz-id-2"]       = hex(32),
    },
    message = string.format("%s from %s executed %s on %s",
      user.name, user.department or "unknown", api, svc),
  }

  -- API-specific extras → merge into requestParameters / additionalEventData.
  local extras = api_extras(api, story)
  if extras then
    if extras.requestParameters then
      for k, v in pairs(extras.requestParameters) do
        record.requestParameters[k] = v
      end
    end
    if extras.additionalEventData then
      for k, v in pairs(extras.additionalEventData) do
        record.additionalEventData[k] = v
      end
    end
  end

  -- 10% chance of surfacing an error to exercise errorCode/errorMessage paths.
  if math.random() < 0.10 then
    if malicious then
      record.errorCode = pick({
        "UnauthorizedAccess", "AccessDenied",
        "TokenRefreshRequired", "InvalidUserID.NotFound",
      })
      record.errorMessage = pick({
        "User suspicious.user is not authorized to perform this action - security alert triggered",
        "Access denied: Suspicious activity detected",
        "Security policy violation detected",
        "Administrative authorization required",
      })
    else
      record.errorCode    = "AccessDenied"
      record.errorMessage = string.format(
        "Insufficient clearance level: %s required for this operation",
        user.clearance or "unknown")
    end
  end

  return record, malicious
end

-- ─────────────────────────── Run plan ──────────────────────────────────────
scenario.run = function(sender, story)
  story:correlate("source_scenario", "aws_cloudtrail.py")

  -- Tunables (override via env or future opts.user_data).
  local normal_count    = 18  -- Phase 1 benign baseline
  local malicious_count = 12  -- Phase 2 high-risk burst
  story:correlate("planned_event_count", normal_count + malicious_count)

  -- ── Phase 1: normal_operations ───────────────────────────────────────────
  story:phase("normal_operations")
  for i = 1, normal_count do
    local payload = build_event(story, i, false)
    sender:hec_event("aws_cloudtrail", payload, {
      phase  = "normal_operations",
      actor  = "corp_users",
      host   = "control_plane",
      offset_seconds = (i - 1) * 30,  -- spread across the phase
    })
  end

  -- ── Phase 2: suspicious_burst ────────────────────────────────────────────
  story:phase("suspicious_burst")
  for i = 1, malicious_count do
    local payload = build_event(story, normal_count + i, true)
    sender:hec_event("aws_cloudtrail", payload, {
      phase  = "suspicious_burst",
      actor  = "attacker",
      host   = "control_plane",
      offset_seconds = (i - 1) * 20,
    })
  end

  -- Bubble up indicators of compromise for the TI pipeline.
  sender:ti(story:iocs(), { phase = "suspicious_burst" })
end

return scenario
