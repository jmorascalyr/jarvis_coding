-- ============================================================================
-- AWS CloudTrail (Lua, single-file generator)
-- ============================================================================
-- Single-file Lua generator that the hec_sender Lua bridge can dispatch.
-- Run via:
--   python Backend/event_generators/shared/hec_sender.py --product aws_cloudtrail_lua -n 100
--
-- The runtime injects a global `helpers` table with deterministic-ish utilities
-- (uuid, sha256, rand_int, pick, fake_*, jitter). No `require` / `io` / `os` —
-- the bridge sandboxes them out.
-- ============================================================================

local h = helpers

local REGIONS = { "us-east-1", "us-east-2", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1" }
local TLS_VERSIONS = { "TLSv1.2", "TLSv1.3" }
local CIPHERS = {
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "TLS_AES_128_GCM_SHA256",
}

local CORPORATE_USERS = {
  { name = "alex.rivera",   role = "platform-engineer", department = "engineering", clearance = "L4", account = "111111111111" },
  { name = "casey.chen",    role = "security-analyst",  department = "security",    clearance = "L5", account = "111111111111" },
  { name = "jordan.patel",  role = "data-engineer",     department = "data",        clearance = "L3", account = "222222222222" },
  { name = "morgan.nguyen", role = "ml-engineer",       department = "ml",          clearance = "L3", account = "222222222222" },
  { name = "taylor.khan",   role = "sre",               department = "platform",    clearance = "L4", account = "333333333333" },
}

local ATTACKER = {
  name = "suspicious.user", role = "external-contractor", department = "unknown",
  clearance = "unauthorized", account = "666666666666",
}

local NORMAL_APIS = {
  { "s3.amazonaws.com",                "GetObject"            },
  { "s3.amazonaws.com",                "PutObject"            },
  { "s3.amazonaws.com",                "ListBucket"           },
  { "ec2.amazonaws.com",               "DescribeInstances"    },
  { "ec2.amazonaws.com",               "RunInstances"         },
  { "iam.amazonaws.com",               "GetUser"              },
  { "iam.amazonaws.com",               "ListUsers"            },
  { "sts.amazonaws.com",               "AssumeRole"           },
  { "kms.amazonaws.com",               "Decrypt"              },
  { "dynamodb.amazonaws.com",          "Query"                },
  { "logs.amazonaws.com",              "PutLogEvents"         },
  { "secretsmanager.amazonaws.com",    "GetSecretValue"       },
}

local MALICIOUS_APIS = {
  { "bedrock-runtime.amazonaws.com",   "InvokeModel"          },
  { "bedrock.amazonaws.com",           "GetFoundationModel"   },
  { "sagemaker.amazonaws.com",         "CreateNotebookInstance" },
  { "dynamodb.amazonaws.com",          "Scan"                 },
  { "kms.amazonaws.com",               "Decrypt"              },
  { "secretsmanager.amazonaws.com",    "GetSecretValue"       },
  { "iam.amazonaws.com",               "CreateAccessKey"      },
  { "iam.amazonaws.com",               "AttachUserPolicy"     },
  { "sts.amazonaws.com",               "AssumeRole"           },
  { "s3.amazonaws.com",                "GetObject"            },
}

local USER_AGENTS = {
  "aws-cli/2.15.9 Python/3.11.4 Linux/5.10",
  "Corporate-Console/1.0 WebUI/2.4.7",
  "Business-SDK/3.2.1 CloudAPI/4.0",
  "aws-sdk-java/2.20.0 Linux/5.15 OpenJDK/17.0.6",
  "Boto3/1.34.0 Python/3.12.1 Darwin/24.0.0",
}

local MALICIOUS_PCT = 0.20

local function principal_id(prefix, user)
  return string.format("%s%s%d", prefix, string.upper(user.department:gsub("-", "")):sub(1, 8), h.rand_int(1000, 9999))
end

local function access_key()
  return "AKIA" .. string.upper(h.uuid():gsub("-", ""):sub(1, 16))
end

local function build_record(i)
  local malicious = math.random() < MALICIOUS_PCT
  local pool = malicious and MALICIOUS_APIS or NORMAL_APIS
  local svc_api = h.pick(pool)
  local svc, api = svc_api[1], svc_api[2]
  local user = malicious and ATTACKER or h.pick(CORPORATE_USERS)
  local region = h.pick(REGIONS)
  local event_id = h.uuid()
  local request_id = h.uuid()

  local record = {
    eventCategory = malicious and "Insight" or h.pick({ "Management", "Data", "Insight" }),
    eventName     = api,
    eventSource   = svc,
    eventTime     = h.now_iso(),
    eventVersion  = "1.09",
    eventID       = event_id,
    eventType     = "AwsApiCall",
    awsRegion     = region,
    readOnly      = (api:sub(1, 3) == "Get") or (api:sub(1, 4) == "List") or (api:sub(1, 8) == "Describe"),
    managementEvent     = true,
    recipientAccountId  = user.account,
    sourceIPAddress     = h.fake_ip(),
    userAgent           = h.pick(USER_AGENTS),
    tlsDetails = {
      tlsVersion              = h.pick(TLS_VERSIONS),
      cipherSuite             = h.pick(CIPHERS),
      clientProvidedHostHeader = svc,
    },
    userIdentity = {
      type        = "IAMUser",
      principalId = principal_id("AIDA", user),
      arn         = string.format("arn:aws:iam::%s:user/%s", user.account, user.name),
      accountId   = user.account,
      accessKeyId = access_key(),
      userName    = user.name,
      sessionContext = {
        sessionIssuer = {
          type        = "Role",
          principalId = principal_id("AROA", user),
          arn         = string.format("arn:aws:iam::%s:role/%s", user.account, user.role),
          userName    = user.role,
          accountId   = user.account,
        },
        attributes = {
          creationDate     = h.now_iso(),
          mfaAuthenticated = malicious and "false" or h.pick({ "true", "false" }),
        },
      },
    },
    requestID = request_id,
    requestParameters = {
      durationSeconds  = 900,
      roleArn          = string.format("arn:aws:iam::%s:role/%s", user.account, user.role),
      roleSessionName  = string.format("%s-session", user.department),
      externalId       = h.uuid(),
    },
    responseElements = {
      assumedRoleUser = {
        assumedRoleId = string.format("%s:%s-session", principal_id("AROA", user), user.department),
        arn = string.format("arn:aws:sts::%s:assumed-role/%s/%s-session", user.account, user.role, user.department),
      },
    },
    sharedEventID = h.uuid(),
    vpcEndpointId = string.format("vpce-%s-%s", user.department:gsub("-", ""):sub(1, 8), h.uuid():gsub("-", ""):sub(1, 9)),
    resources = {
      {
        accountId = user.account,
        type      = "AWS::S3::Bucket",
        ARN       = string.format("arn:aws:s3:::corp-%s-%s", user.department, h.rand_int(1, 999)),
      },
    },
    additionalEventData = {
      SignatureVersion       = "SigV4",
      CipherSuite            = h.pick(CIPHERS),
      bytesTransferredIn     = 0,
      bytesTransferredOut    = h.rand_int(512, 10240),
      AuthenticationMethod   = "AuthHeader",
    },
    message = string.format("%s from %s executed %s on %s", user.name, user.department, api, svc),
  }

  -- 10% chance of surfacing errorCode/errorMessage for parser coverage.
  if math.random() < 0.10 then
    if malicious then
      record.errorCode    = h.pick({ "UnauthorizedAccess", "AccessDenied", "TokenRefreshRequired" })
      record.errorMessage = "Access denied: suspicious activity detected"
    else
      record.errorCode    = "AccessDenied"
      record.errorMessage = string.format("Insufficient clearance level (%s required)", user.clearance)
    end
  end

  return record
end

-- ============================================================================
-- Header table — REQUIRED by the Lua bridge
-- ============================================================================
return {
  id          = "aws_cloudtrail_lua",
  category    = "cloud_infrastructure",
  name        = "AWS CloudTrail (Lua)",
  vendor      = "AWS",
  product     = "CloudTrail",
  sourcetype  = "aws_cloudtrail-latest",
  hec_path    = "event",
  description = "Single-file Lua port of the Python aws_cloudtrail generator. Mixed benign / malicious management-event traffic across IAM, S3, Bedrock, SageMaker, DynamoDB, KMS.",

  -- Called once per event by the bridge. `state` is a fresh Lua table (per
  -- runtime) so generators can carry counters between calls without leaking
  -- across processes.
  emit = function(state, i)
    state.count = (state.count or 0) + 1
    return build_record(state.count)
  end,
}
