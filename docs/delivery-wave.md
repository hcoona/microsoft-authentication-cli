# Current Delivery Wave

This record is the sole positive work-authorization authority. An entry is authorized
only as accepted on `main-v2`. An Issue, Milestone, branch, pull request, comment, label,
or unmerged edit cannot add to or enlarge this record.

Adding or changing an entry through merge grants or changes its bounded authorization.
Deleting an entry through merge ends that authorization. Git and the proposing pull
request retain the reason and history; this record contains no progress or historical
status.

Preparing and reviewing an explicitly repository-owner-approved pull request whose sole
substantive purpose is to change this record is permitted without an existing entry. The
proposal does not authorize any work it would add before merge.

## Authorized Advancements

### First Windows Authentication Slice: Implementation and Scenario Acceptance

The repository owner authorizes advancement toward acceptance of the personal-account
primary journey and work-account variant in the existing
[Windows Slice design](designs/windows-ado-authentication.md). [Issue #108](https://github.com/hcoona/microsoft-authentication-cli/issues/108)
owns progress; the existing [validation strategy](validation/strategy.md#windows-slice-design-acceptance)
owns scenario and evidence obligations. Completion requires the evidence appropriate to
each scenario; controlled substitutes do not establish real WAM, UI, reuse, or WSL behavior.

**Accepted inputs:** the product requirements and user stories; architecture overview,
request lifecycle and client-identity views; Windows design and protocol 1 schemas;
security narrative/native TMT model; validation strategy; and the accepted public-source,
Windows account and Native AOT research with their recorded limitations. Retain .NET
SDK 10.0.401/runtime 10.0.12, MSAL/Broker 4.83.1 and NativeInterop 0.20.3.

**Bounded advancement:** refine acceptance cases against the existing requirements;
implement the selected Windows x64 CLI, core rules, WAM adapter and owned Win32 host;
add scenario-led and public-contract tests with focused core-rule unit tests; establish
the necessary minimal project/build organization and public dependency locks; and review
the implemented source, security, provenance and exact Native AOT artifact. Maintain the
existing canonical consumers and applicable control routing in the same changes. Resolve
material design or operational-identity prerequisites before their dependent implementation.
Any reuse of Lasso-dependent components retains its separate architecture prerequisite.

**Execution envelope:** prepare and independently accept a tracked protocol before any
covered restore, build, test, publish or subject execution. It may cover the existing
WSL2 Linux x64 development environment for controlled tests and the existing Windows 11
x64 interactive host for public Native AOT compilation and synthetic host/pipe tests.
Use only public dependencies and verified retained public caches/installed toolchains;
downloads may use public NuGet.org and official .NET distribution endpoints, with no
credentials. New experiment-owned files stay in dedicated build/test roots outside
production installations and are intentionally retained. Maximum cumulative capacity is
16 dependency preparation/restore actions, 120 build/test actions, 12 Native AOT publish
actions and 40 synthetic process scenarios, with at most 4 GiB of newly downloaded public
dependency content. Exact per-action time, output and termination limits and source
admission are owned by the accepted protocol. No new toolchain installation is granted.

**Account and external-effects boundary:** this entry permits only credential-free
synthetic execution and preparation of the remaining real-environment protocols. No
account enumeration, token acquisition, account/cache/consent change, authenticated
resource request or real WAM interaction may execute under this envelope. Before those
necessary later acceptance steps, accept an amendment containing the concrete
repository-owner risk decision and an independently accepted exact protocol. Keep the
overall Slice acceptance open until its required evidence is accepted; these gates do
not redefine the outcome as synthetic-only acceptance. Historical experiments and
their consumed capacity remain unchanged and cannot be replayed under this entry.

**Exclusions:** no product or protocol expansion, PATs, downstream Git/package adapters,
browser/device-code or native Linux/macOS/ARM64 authentication, daemon, serialized
application cache, private dependency, network telemetry export, installation, signing,
release, automatic Profile activation/provisioning or general platform support claim.
Profile distribution and release retain their separate gates. After the bounded scenario
outcome is accepted, remove this grant through a reviewed Wave change.
