# CoralCollective 🪸

The collective intelligence for evolutionary development - 21 specialized AI agents working as a unified colony to build your digital reef.

## 🚀 Quick Start

### Option 1: Drop-in Integration (Existing Projects)
```bash
# Copy coral_drop.sh to existing project
./coral_drop.sh
# Creates hidden .coral/ directory
# Adds 'coral' command wrapper
# Non-invasive, respects existing structure

# Use agents
./coral list
./coral workflow
```

### Option 2: Run from Source
```bash
# Install dependencies
pip install -r requirements.txt

# Launch CoralCollective
./start.sh

# Set up MCP integration (optional but recommended)
./mcp/setup_mcp.sh
```

## 🎯 Claude Integration - NEW!

CoralCollective agents are now available as Claude subagents:

```python
# Direct invocation in Claude
@backend_developer "Create REST API with authentication"
@frontend_developer "Build React dashboard"
@qa_testing "Write comprehensive tests"

# Run complete workflows
@workflow full_stack "Build e-commerce platform"

# Chain agents
@chain [@architect, @backend, @frontend] "Create todo app"
```

See [CLAUDE.md](CLAUDE.md) for Claude-specific integration.

## 📋 Documentation-First Workflow

### Phase 1: Planning & Foundation
1. **Project Architect** - Creates technical plan and project structure
2. **Technical Writer (Phase 1)** - Creates documentation foundation and requirements

### Phase 2: Development to Specification  
3. **Backend Developer** - Builds APIs following documented specs
4. **AI/ML Specialist** - Implements AI features per requirements
5. **Frontend Developer** - Creates UI following specifications
6. **Security Specialist** - Implements security per standards

### Phase 3: Quality & Deployment
7. **QA & Testing** - Tests against documented acceptance criteria
8. **DevOps & Deployment** - Deploys following documented procedures

### Phase 4: Documentation Completion
9. **Technical Writer (Phase 2)** - Finalizes user documentation and guides

## 🤖 Available Agents

### Core Agents
- **[Project Architect](agents/core/project_architect.md)** - System design and architecture
- **[Technical Writer](agents/core/technical_writer.md)** - Documentation specialist (2 phases)

### Specialist Agents
- **[Backend Developer](agents/specialists/backend_developer.md)** - Server and database specialist
- **[Frontend Developer](agents/specialists/frontend_developer.md)** - UI/UX implementation
- **[AI/ML Specialist](agents/specialists/ai_ml_specialist.md)** - AI integration expert
- **[Security Specialist](agents/specialists/security_specialist.md)** - Security and compliance
- **[DevOps & Deployment](agents/specialists/devops_deployment.md)** - Infrastructure specialist
- **[QA & Testing](agents/specialists/qa_testing.md)** - Quality assurance expert
- **[Model Strategy Specialist](agents/specialists/model_strategy_specialist.md)** - AI model optimization & cost management

## 📁 Project Structure

```
coral_collective/
├── agents/
│   ├── core/                    # Core workflow agents
│   │   ├── project_architect.md
│   │   └── technical_writer.md
│   ├── specialists/              # Specialist agents (20+ total)
│   │   ├── backend_developer.md
│   │   ├── frontend_developer.md
│   │   ├── model_strategy_specialist.md
│   │   └── ...
│   ├── assessment/               # Assessment and validation agents
│   └── agent_orchestrator.md    # Workflow management guide
├── mcp/                         # Model Context Protocol integration
│   ├── servers/                 # MCP server implementations
│   ├── configs/                 # MCP configurations
│   ├── mcp_client.py           # Python MCP client
│   └── setup_mcp.sh            # MCP setup script
├── config/
│   ├── agents.yaml             # Agent registry
│   └── model_assignments_2025.yaml  # AI model configurations
├── tools/                       # Utility scripts
├── claude_interface.py          # Main Python interface for Claude integration
├── subagent_registry.py         # Subagent orchestration and invocation
├── claude_code_agents.json      # Agent registry and workflow definitions
├── deploy_coral.sh              # Deployment script
├── coral_drop.sh                # Drop-in integration for existing projects
├── MODEL_OPTIMIZATION_STRATEGY.md   # 2025 model pricing & strategy
├── MCP_INTEGRATION_STRATEGY.md      # MCP implementation guide
├── INTEGRATION.md               # Complete integration guide
└── README.md                    # This file
```

## 🆕 Recent Updates

### Major Consolidation (2025-02)
- **Simplified Integration**: Consolidated multiple Python files into `claude_interface.py` and `subagent_registry.py`
- **Unified Configuration**: Single `claude_code_agents.json` for all agent configurations
- **Streamlined Documentation**: All integration guides merged into `INTEGRATION.md`
- **Deployment Scripts**: New `deploy_coral.sh` and `coral_drop.sh` for easy deployment

## 🆕 New Features (2025)

### MCP Integration (Model Context Protocol)
- **Direct Tool Access**: Agents can interact directly with GitHub, databases, Docker, and more
- **Secure Execution**: Sandboxed file operations and code execution via E2B
- **15+ MCP Servers**: Pre-configured integrations with popular development tools
- **Agent Permissions**: Each agent has specific tool access based on role

### AI Model Optimization
- **2025 Model Support**: GPT-5, Claude Opus 4.1, and efficiency models
- **60-70% Cost Reduction**: Smart model selection based on task complexity
- **Dynamic Routing**: Automatic selection of best model for each task
- **Caching Strategies**: 90% savings on repeated operations

## 💡 How It Works

1. **Structured Handoffs**: Each agent provides specific handoff instructions
2. **Documentation-First**: Requirements documented before development begins
3. **Consistent Structure**: All agents follow the same project organization
4. **Clear Responsibilities**: Each agent has specific deliverables
5. **Quality Focus**: Built-in testing and security considerations
6. **Tool Integration**: Direct access to development tools via MCP
7. **Cost Optimization**: Intelligent AI model selection for efficiency

## 📊 When to Use Each Agent

| Scenario | Recommended Agents |
|----------|-------------------|
| Full-Stack Web App | All agents in sequence |
| API Service | Architect → Writer → Backend → Security → QA → DevOps |
| Frontend Only | Architect → Writer → Frontend → QA → DevOps |
| AI-Powered App | All agents (AI/ML Specialist required) |
| MVP/Prototype | Architect → Backend → Frontend (minimal set) |

## 🔄 Agent Handoff Protocol

Each agent provides:
1. **Completion Summary** - What was delivered
2. **Next Agent Recommendation** - Who should work next
3. **Exact Next Prompt** - Copy-paste ready prompt
4. **Context for Next Agent** - Critical information
5. **Additional Notes** - Special considerations

## 🎯 Best Practices

### Do's
- ✅ Always start with Project Architect
- ✅ Follow the documentation-first approach
- ✅ Use handoff instructions exactly as provided
- ✅ Complete each phase before moving forward
- ✅ Maintain the established project structure

### Don'ts
- ❌ Skip the planning phase
- ❌ Jump directly to development
- ❌ Ignore handoff instructions
- ❌ Mix phases together
- ❌ Create files outside the defined structure

## 📚 Example Workflows

### Building a Task Management App
```
1. Project Architect: "I want a task management app with team collaboration"
2. Technical Writer Phase 1: Creates requirements and API specs
3. Backend Developer: Builds task API, user management
4. Frontend Developer: Creates task UI, team features
5. Security Specialist: Implements authentication, permissions
6. QA & Testing: Tests all features
7. DevOps: Deploys to production
8. Technical Writer Phase 2: Creates user guide
```

### Examples Folder
- `examples/web_app_standard/` contains a minimal docs structure and a sample state file at `.agent_force/state.json.example` to illustrate expected outputs for validators and workflows.

### Tests
- Basic tests live in `tests/`:
  - `tests/test_agent_manager_workflow.py`: Loads a YAML template and validates phase transitions.
  - `tests/test_state_persistence.py`: Verifies save/load state.
- Run with your preferred test runner (e.g., `pytest`). No extra deps beyond PyYAML for YAML parsing.

## 🛠 CLI Runner (Experimental)

The minimal CLI helps you list templates, load workflows, register agents, inspect phase status, and save/load state.

Commands:

```bash
# List available workflow templates
python tools/runner.py list-templates

# Initialize a project context
python tools/runner.py init --project-name MyApp --project-path $(pwd)

# Load a workflow (e.g., standard web app)
python tools/runner.py load-workflow web_app_standard --yaml workflows/project_templates.yaml

# Register all agents from the registry
python tools/runner.py register-all --registry config/agents.yaml

# Show current workflow status and current phase agents
python tools/runner.py status
python tools/runner.py phase

# Save or load state
python tools/runner.py save-state .agent_force/state.json
python tools/runner.py load-state .agent_force/state.json
```

## ✅ Validation CLI

Use the validation tool to check agent dependencies and required outputs per phase.

```bash
# Validate the current phase against a template and saved state
python tools/validate.py current \
  --state .agent_force/state.json \
  --yaml workflows/project_templates.yaml \
  --template-key web_app_standard

# Validate a specific agent's dependencies
python tools/validate.py agent frontend_developer \
  --state .agent_force/state.json \
  --yaml workflows/project_templates.yaml

# Validate all phases for a template
python tools/validate.py all \
  --state .agent_force/state.json \
  --yaml workflows/project_templates.yaml \
  --template-key web_app_standard
```

Notes:
- Both runner and validator expect PyYAML installed if using YAML configs.
- Technical Writer is modeled as two IDs: `technical_writer_phase1` and `technical_writer_phase2`, both referencing `agents/core/technical_writer.md` with phase-specific responsibilities.

### Additional Commands

```bash
# Print an agent's prompt to stdout
python tools/runner.py prompt backend_developer

# Execute a simple task and (optionally) autosave state
python tools/runner.py run backend_developer --name "scaffold api" --data '{"scope":"users"}' --autosave .agent_force/state.json
```

### Security & Documentation Baselines
- See `SECURITY.md` for policy and practices.
- The validator warns if `SECURITY.md` or key docs folders are missing.

### Creating an AI Chat Application
```
1. Project Architect: "Build a customer support chatbot"
2. Technical Writer Phase 1: Documents AI requirements
3. Backend Developer: Creates chat infrastructure
4. AI/ML Specialist: Integrates LLM, sets up vector DB
5. Frontend Developer: Builds chat interface
6. Security Specialist: Secures API keys, user data
7. QA & Testing: Tests AI responses, edge cases
8. DevOps: Deploys with monitoring
9. Technical Writer Phase 2: Documents bot capabilities
```

## 🛠️ Customization

Each agent prompt can be customized for your specific needs:
- Adjust tech stack preferences
- Add company-specific standards
- Include compliance requirements
- Modify handoff workflows

## 🤝 Integration with Development Tools

All agents are optimized for:
- **Claude Code**: AI-powered development assistance
- **Claude Code IDE**: AI-first code editor
- **TypeScript**: Type-safe development
- **Modern Frameworks**: React, Next.js, Node.js, etc.

## 📈 Success Metrics

Projects using this agent system typically achieve:
- 🎯 Clear project structure from day one
- 📝 Comprehensive documentation throughout
- 🔒 Security considerations built-in
- 🧪 Thorough testing coverage
- 🚀 Smooth deployment process
- 📚 Complete user documentation

## 🆘 Troubleshooting

| Problem | Solution |
|---------|----------|
| Unclear requirements | Return to Technical Writer Phase 1 |
| Architecture issues | Re-engage Project Architect |
| Integration problems | Check agent handoff context |
| Testing failures | Review with QA & Testing agent |
| Deployment issues | DevOps agent handles infrastructure |

## 🎓 Learning Resources

- [Agent Orchestrator Guide](agents/agent_orchestrator.md) - Complete workflow management
- Individual agent files contain detailed prompts and examples
- Examples folder contains sample projects (coming soon)

## 🚦 Getting Started Checklist

- [ ] Read this README completely
- [ ] Review the Agent Orchestrator guide
- [ ] Choose your project type
- [ ] Start with Project Architect agent
- [ ] Follow the handoff chain
- [ ] Complete all phases
- [ ] Deploy your application!

## 📞 Support

For questions or improvements:
- Review individual agent documentation
- Check the orchestrator guide for workflow help
- Customize prompts for your specific needs

## 🎉 Ready to Build?

1. Open `agents/core/project_architect.md`
2. Copy the prompt
3. Start building with your AI development team!

---

**Remember**: The key to success is following the documentation-first workflow and trusting the handoff process between agents. Each specialist adds unique value to your project!
