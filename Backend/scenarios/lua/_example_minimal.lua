return {
  id = "minimal-lua-example",
  name = "Minimal Lua Scenario Example",
  description = "Two portable events demonstrating the Lua scenario API.",
  version = 1,
  mitre = { "T1078" },

  actors = {
    { id = "victim", role = "user", name = "Alex Rivera", email = "alex@example.com", username = "alex.rivera", domain = "EXAMPLE" },
    { id = "attacker", role = "threat", ip = "203.0.113.10", country = "Exampleland" },
  },

  hosts = {
    { id = "workstation", name = "HOST-001", os = "Windows", type = "workstation", internal_ip = "10.0.0.25", primary_user = "victim" },
  },

  timing = {
    base = { mode = "fixed_offset", offset_seconds = 0 },
    jitter_seconds = 0,
    duration_minutes = 5,
    phases = {
      identity_abuse = { offset_minutes = 0 },
      endpoint_activity = { offset_minutes = 2 },
    },
  },

  run = function(sender, story)
    story:phase("identity_abuse")
    sender:hec_event("okta_authentication", {
      eventType = "user.authentication.sso",
      severity = "WARN",
      displayMessage = "Suspicious SSO from unfamiliar IP",
      client = { ipAddress = story:actor("attacker").ip },
      outcome = { result = "SUCCESS", reason = "Valid credentials" },
    }, { actor = "victim", offset_seconds = 0 })

    story:phase("endpoint_activity")
    sender:hec_event("sentinelone_endpoint", {
      ["event.type"] = "Process Creation",
      ["endpoint.name"] = story:host("workstation").name,
      ["src.process.name"] = "powershell.exe",
      ["src.process.cmdline"] = "powershell.exe -NoProfile -ExecutionPolicy Bypass",
    }, { actor = "victim", host = "workstation", offset_seconds = 0 })
  end,
}
