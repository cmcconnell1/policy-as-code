
Create working code project demo supporting both AWS and Azure.

Cloud Security Engineers utiliyt/tool/project for financial services industry.
 
Key Responsibilities project must demo with documentation:
Develop Sentinel (is there a free version--how can this be done without a paid account? is it possible if not use Reo--see below) mocks and tests to ensure policy enforcement.
Integrate and automate cloud security controls across AWS and Azure.
Maintain situational awareness of the security landscape within a banking environment.
Execute tasks efficiently, leveraging documentation and direct communication to overcome obstacles.
 
Key Requirements:
Policy as Code: Strong experience with Rego and/or HashiCorp Sentinel.
Cloud Security Proficiency: Deep expertise in both AWS and Azure security.
Infrastructure as Code: Proficiency with Terraform is required; Sentinel experience is a significant bonus.
Coding Proficiency: Strong skills in Python or an equivalent language are necessary. Candidates should be well beyond basic programming concepts like "if" statements and "for" loops.
DevSecOps Mindset: This is not a pure DevOps role or a role solely focused on vulnerability remediation. The ideal candidate has a comprehensive DevSecOps background.
Cloud Policy: Demonstrable experience with native cloud policy frameworks in Azure and AWS.
 
Azure Experience and examples are Mandatory: we must provide documented tools and process for both azure and aws clouds.
A strong, demonstrable proficiency in Azure security is a non-negotiable requirement for this project.
Execution-Focused Role: 
DevSecOps, Not Just DevOps: There is a critical distinction for this role. Previous projects were rejected for only having a strong DevOps automation background but lacking sufficient depth in core security principles. This is a security-first project. we must demonstrate DevSecOps—integrating security controls and thinking defensively—not just automating infrastructure and pipelines.

Reporting:
must automate cloud environment reports for scheduled and add-hoc jobs using github actions
create best practices reports including baseline best practices and more advanced etc


Notes:
in case its useful see a similar project proof of concept / MVP available here: ../iam-multicloud/
we may be able to leverage existing code/tools for reporting etc
top level readme.md should be clean and have table of contents linked to additional ./docs/* files

below are my initial assumptions and may not be accurate/correct, claude should validate and follow industry best practices

Pattern: Keep Policies in Their Own Repo?

Large orgs (banks, fintech, SaaS) use this structure:

infra-repo/                     → Terraform, Helm, manifests, pipelines  
policy-as-code/                 → All Rego + Sentinel policies  
    /opa-rego/
    /sentinel/

anticipated project org/structure is this correct?

policy-as-code/
└── opa-rego/
    ├── policies/
    │   ├── enforce-tags.rego
    │   ├── deny-public-s3.rego
    │   └── require-kms-encryption.rego
    ├── tests/
    │   ├── enforce-tags_test.rego
    │   ├── deny-public-s3_test.rego
    │   └── require-kms-encryption_test.rego
    ├── data/
    │   ├── s3.json
    │   └── tags.json
    ├── ci/
    │   └── github-actions.yaml
    └── README.md
 └── sentinel/
     ├── policies/
     ├── mocks/
     └── ci/

Where Policies Live (recommended topology) is this correct?
Component	Repo	Reason
Terraform, Kubernetes, Infra code	infra-repo	Separated from policy governance
OPA / Sentinel Policies	policy-as-code	Centralized security rules
Data mocks	policy-as-code/data	Reproducible testing
CI pipelines	Inside policy repo	Fails fast when policy logic breaks
Terraform calling policies	in infra-repo	Local or remote bundles


what other best practices/suggestions etc does claude recommend?
