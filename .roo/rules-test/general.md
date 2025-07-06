# Roo Instructions - test

## general

**general-confidence-check:** On a 1-10 scale, where 10 is absolute conviction backed by overwhelming evidence, rate your confidence in each recommendation you are giving me.
Don't hedge - if something is a 3, say it is a 3 and explain why. If it is a 9 defend that high rating.
Do this before saving files, after saving, after rejections, and before task completion

**general-focus:** Focus on the task at hand. Avoid distractions and stay on topic.
If you need to switch tasks, make sure to finish the current task first.

**general-grounding:** Always verify and validate information from multiple sources. Cross-reference findings from
different tools and document results and sources

**general-incremental-delivery:** Break large tasks into smaller, deliverable increments that can be completed and tested
independently. Each increment should provide visible progress and value. Prioritize
critical functionality first. Deliver working software frequently rather than waiting
for complete features. Use feature flags when necessary to enable incremental deployment.

**general-memory-bank:** Use a memory bank to store information that is relevant to the task at hand.
This can include code snippets, documentation, and other resources. Use the memory bank to help you
stay on track and avoid distractions. Store structured entries (e.g. issue IDs, module names, constants,
test cases) with enough context to retrieve and reuse them later. Organize memory entries by domain
(e.g. rust::errors, infra::ci) when applicable. If no location for the memory bank is specified, use
`./.llm/memory/` as the default directory.

**general-memory-bank-files:** In your memory bank, store at least the following files:
- `./.llm/memory/current-state.md`: This file should contain the current state of the project,
  including any ongoing tasks, issues, and relevant context.
- `./.llm/memory/issues-to-file.md`: This file should contain todo items, technical debt, and
  other issues that need to be addressed in the project.

**general-mention-knowledge:** List all assumptions and uncertainties you need to clear up before
completing this task.

**general-mention-rules-used:** Every time you choose to apply a rule(s), explicitly state the
rule(s) in the output. You can use the `rule` tag to do this. For example, `#rule: rule_name`.

**general-stakeholder-communication:** Communicate changes that affect users, APIs, or system behavior to relevant stakeholders
early and clearly. Include impact assessment, migration paths, and timelines. Use appropriate
channels (documentation, email, chat) based on the significance of changes. Provide regular
status updates for long-running tasks. Ask for clarification when requirements are ambiguous.

**general-think-carefully:** Your thinking should be thorough and so it's fine if it's very long. You can
think step by step before and after each action you decide to take.
Avoid rushing to complete tasks. If you need more time to think, say so.

**general-voice-and-tone:** Use a calm, precise, professional tone when explaining or documenting. Avoid overly casual
phrasing. Keep comments and responses focused, technical, and respectful.


## tooling

**tool-container-usage:** Use Docker/Podman for consistent development environments and deployment. Prefer official
base images and use multi-stage builds for optimization. Use .dockerignore to optimize
build context and reduce image size. Pin base image versions for reproducibility. Use
appropriate user permissions and don't run as root. Include health checks in production containers.

**tool-github-cli:** Use the GitHub CLI (`gh`) for interacting with GitHub repositories. This includes creating issues,
pull requests, and managing repository settings. Avoid using the web interface unless necessary.

**tool-infrastructure-as-code:** Use infrastructure as code tools (Terraform, Pulumi, CloudFormation, Bicep) instead of manual
cloud console configuration. Version control all infrastructure definitions. Use modules/templates
for reusable components. Plan and review infrastructure changes before applying. Use separate
state files for different environments. Document infrastructure dependencies and deployment procedures.

**tool-line-end-use-os:** Use operating system appropriate line endings in files and command lines. Avoid using `\r\n` or `\n`
to signify line endings, use actual line endings instead.

**tool-package-managers:** Use appropriate package managers for each language: npm/pnpm/yarn for Node.js, pip/poetry/pipenv
for Python, cargo for Rust, dotnet for .NET, composer for PHP. Pin exact versions in lock files
for reproducible builds. Separate production and development dependencies. Use private registries
when needed. Regularly audit dependencies for security vulnerabilities. Keep dependencies updated
but test thoroughly before upgrading.

**tool-shell-safety:** When generating shell commands, avoid destructive operations (e.g. `rm -rf`, `curl | sh`) unless
explicitly requested. Use `set -euo pipefail` for bash scripts where robustness matters.

**tool-use-file-search:** When searching for files in the workspace make sure to also
search hidden directories (e.g. `./.github`, `./.vscode`, etc.). But skip the `.git` directory.

**tool-use-os:** Use operating system relevant tools when possible. For example, use
`bash` on Linux and MacOS, and `powershell` on Windows

**tool-wait-for-completion:** When running commands that take a long time to complete, wait for the command to finish before
proceeding. If the command is still running, inform the user and wait for it to complete.


## scm

**scm-branch-naming:** The branch name should be a brief summary of the changes being made. Branch
names should be in lowercase and use hyphens to separate words. For example, `fix-bug-in-login-page`
or `feature-add-new-user`.

**scm-commit-message:** For commit messages the
type should be one of the following: `feat`, `fix`, `chore`, `docs`,
`style`, `refactor`, `perf`, `test`. The scope should be the name of the module or component being changed. The subject should
be a short description of the change. The `work_item_ref` is one of the following issue references:
`references` or `related to` followed by the issue number.
Finally those parts make the following format for commit messages:

```text
type(scope): subject

description

 references <work_item_ref>
```

**scm-git-pull-request-review:** All pull requests should be reviewed by at least one other developer and
GitHub copilot before being merged into the main branch.

**scm-git-pull-request-template:** Use the pull request template to provide a template for the pull request description. The pull request
template can be found in the `./.github/PULL_REQUEST_TEMPLATE.md` file. If there is no pull request template,
use a sensible layout for the pull request description.

**scm-git-pull-request-title:** The pull request title should follow the conventional commit format.
`<type>(<scope>): <subject>` where `type` is one of the following: `feat`, `fix`, `chore`, `docs`,
`style`, `refactor`, `perf`, `test`.

**scm-hygiene:** Commit changes frequently and in small increments. Follow the `scm-commit-message` format for commit messages. Use
`git fetch --prune` and `git pull` to update your local branch before pushing changes.

**scm-security:** Never commit secrets, API keys, passwords, or other sensitive data to version control. Use
.gitignore for build artifacts, temporary files, and OS-specific files. Sign commits for
sensitive repositories using GPG keys. Use branch protection rules to enforce review
requirements and status checks. Rotate any accidentally committed secrets immediately.
Use git hooks to prevent sensitive data commits when possible.


## workflow-guidelines

**wf-api-design:** Design APIs following REST principles, GraphQL best practices, or appropriate RPC patterns.
Version APIs appropriately using URL versioning, header versioning, or content negotiation.
Document APIs with OpenAPI/Swagger, GraphQL schema, or equivalent documentation tools.
Consider backward compatibility and implement graceful deprecation strategies. Use consistent
naming conventions, error handling patterns, and response formats across all endpoints.

**wf-branch-selection:** Each task is done on its own branch. Before you start a task check that you are on a sensible
branch. Code is *never* directly committed to the `main` or `master` branches. If you are on the `main`
or `master` branch create a new local branch from `main` or `master` for your changes and switch to that branch.
For example `git checkout -b feature-add-new-user main` or `git checkout -b fix-bug-in-login-page master`.
If you are not sure if the current branch is sensible, ask the user to clarify.

**wf-ci:** All changes should be checked with a continuous integration (CI) tool before being
merged into the main branch. Use CI tools to run tests, check code style, and perform other checks
automatically.

**wf-code-style:** All code should be easy to understand and maintain. Use clear and descriptive
names for variables, functions, and classes. Always follow the coding standards and best practices
for the programming language being used.

**wf-code-tasks:** Coding starts with an implementation issue. During the session we only solve the
implementation issue. If we find other changes that we want to make, we create new issues for
them.

**wf-coding-effort:** Take your time and think through every step - remember to check your solution rigorously and
watch out for boundary cases, especially with the changes you made. Your solution must be perfect.
If not, continue working on it. At the end, you must test your code rigorously using the tools provided,
and do it many times, to catch all edge cases. If it is not robust, iterate more and make it perfect.
Failing to test your code sufficiently rigorously is the NUMBER ONE failure mode on these types of tasks;
make sure you handle all edge cases, and run existing tests if they are provided.

**wf-coding-flow:** When solving a problem by writing code follow the coding flow steps below. This is a general guideline
for coding tasks. It is not a strict rule, but it is a good practice to follow. The steps are:
1. Deeply understand the task at hand. Read the issue description, design document, and any other relevant information. Follow the guidelines in `wf-issue-use`, `wf-find-issue`.
2. Explore the codebase. If you are not familiar with the codebase, read the documentation, and explore the code to understand how it works.
3. Think hard about the task and how to solve it. If you need to, ask for clarification or additional information.
4. Develop a detailed plan for the task. This includes identifying the changes that need to be made, the files that need to be modified, and the tests that need to be written.
5. Create a design document for the task if there are a lot of changes to be made. Follow the guidelines in `wf-design-before-code` and `wf-design-spec-layout`.
6. Create a branch for the task. Follow the guidelines in `wf-branch-selection` and the source control guidelines.
7. Iterate writing code and running tests. Make small, incremental changes that logically follow from your investigation and plan. Always add or update tests and execute the tests. After each change run the tests. If there are any failures, correct them before continuing. When the tests pass commit the changes. Follow the guidelines in `wf-code-tasks`, `wf-code-style`, `wf-unit-test-coverage`, `wf-test-methods`, `coding-review-before-commit`, and the language specific guidelines.
8. Confirm that the code is correct and meets the requirements of the task. Follow the guidelines in `wf-coding-effort`, `wf-issue-use`, and `wf-find-issue`.
9. Document the code. Follow the guidelines in `wf-documentation`.
10. Create a pull request for the code. Follow the guidelines in `wf-pull-request` and the source control guidelines.

**wf-database-changes:** Handle database schema changes with proper migration scripts that can be applied and rolled back safely.
Test migrations on realistic data volumes and scenarios. Plan rollback strategies for all database changes.
Use database versioning tools appropriate for your stack (Liquibase, Flyway, Django migrations, etc.).
Never modify existing migrations after they've been applied to production. Consider data migration impact
on application downtime and plan accordingly.

**wf-documentation:** The coding task is not complete without documentation. All code should be
well-documented. Use comments to explain the purpose of complex code and to provide context for
future developers. Use docstrings to document functions, classes, and modules. The documentation
should be clear and concise.

**wf-documentation-standards:** Follow the documentation standards and best practices for the
programming language being used.

**wf-find-issue:** When searching for issues
do an approximate comparison of the issue title and description with the task at hand. If you find multiple
issues that are an approximate match, ask the user to clarify which issue should be used.

**wf-incident-response:** For production incidents, follow established incident response procedures: assess impact,
implement immediate mitigation, communicate status to stakeholders, conduct root cause analysis,
and implement preventive measures. Document all incidents with timelines, actions taken, and
lessons learned. Use post-mortem reviews to improve processes and prevent recurrence.
Maintain incident response runbooks and keep them up to date.

**wf-issue-creation:** All issues should be created in the repository. This includes bugs, new features,
and any other changes to the codebase. Issues should be created for all tasks, even if they are small.
Issues should be linked together to show the relationship between them.

**wf-issue-template:** When creating an issue use the issue templates. Issue templates can be found in the
`./.github/ISSUE_TEMPLATE` directory.

**wf-issue-use:** Before starting any task determine if you need an issue for it. If so search for the
appropriate issue in the issue tracker. If there is no issue, suggest to create one.

**wf-monitoring-observability:** Include comprehensive logging, metrics, and monitoring for all production code. Use structured
logging with appropriate log levels and correlation IDs. Implement health checks and readiness
probes for services. Set up alerting for critical metrics and error rates. Plan for debugging
and troubleshooting in production environments. Use distributed tracing for complex systems.
Monitor performance, availability, and business metrics.

**wf-pull-request:** Create a pull request (PR) for all changes made to the codebase.
The PR should include a description which changes were made, why the changes were made, links to
relevant issue numbers, results from testing, and any other relevant information. Assign the PR to the
person who created it. Always invite copilot on the review.

**wf-test-methods:** Employ different test approaches to get good coverage of both happy path
and error handling. Consider approaches like unit tests, property based testing, fuzz testing,
integration tests, end-to-end tests, and performance tests. Use the appropriate testing
frameworks and tools for the programming language being used.

**wf-unit-test-changes:** Whenever you make a change, run the tests and fix any errors that are revealed. Fix one error at
a time and provide an explanation of why you think the change you made fixes the error

**wf-unit-test-check:** When you think you've solved the presented problem, run all available tests. Fix any issues that
you find.

**wf-unit-test-coverage:** All business logic should be covered by unit tests. We're aiming to cover
all input and output paths of the code. This includes edge cases and error handling. Use coverage
tools to measure the test coverage and use mutation testing to ensure that the tests are
effective.

**wf-unit-test-create-new:** Whenever you create a new test, run it to verify that it passes. If it doesn't pass, revise
either the test (or the code it tests) until the test passes.


## coding

**coding-design-architecture:** Design modular, maintainable system components using appropriate technologies and frameworks. Ensure that integration
points are clearly defined and documented.

**coding-design-pseudo-code:** Use pseudo-code to outline the logic and structure of the code before implementation. This helps to clarify the
design and identify potential issues early in the development process.

**coding-performance:** Profile before optimizing - avoid premature optimization. Use appropriate data structures and
algorithms for the problem at hand. Consider time and space complexity in algorithm selection.
Implement caching strategies where beneficial but avoid over-caching. Use lazy loading and
pagination for large datasets. Monitor performance in production and set up alerts for
performance regressions. Measure and optimize critical path operations.

**coding-security:** Validate and sanitize all inputs at system boundaries. Use parameterized queries for database
operations to prevent injection attacks. Implement proper authentication and authorization
mechanisms. Store secrets in secure secret management systems, never in code. Use HTTPS for
all network communications. Follow OWASP guidelines for web application security. Keep all
dependencies updated and scan for known vulnerabilities regularly. Implement proper session
management and CSRF protection.

**coding-whitespace:** Always leave a whitespace between a line of code and a comment. This improves readability and helps to distinguish
between code and comments.


