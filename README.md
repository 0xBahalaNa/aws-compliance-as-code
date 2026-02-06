# AWS Compliance as Code

This repository implements Infrastructure as Code (IaC) in AWS by deploying resources via a CloudFormation template and accompanying Service Control Policies (SCPs). 

The purpose of this project is to transform compliance requirements into automated, enforceable, self-documenting code.

The goal of this project is gain hands on GRC Engineering experience and shift from understanding concepts to writing actual code that deploys secure infrastructure and enforces organizational guardrails automatically. 

This repository contains:
- A CloudFormation template that deploys a compliant, secure bucket.
- SCPs that enforce organizational guardrails. 
- README instructions on how to deploy the aforementioned via AWS CLI. 

## AWS Services Used 
- [AWS Organizations](https://aws.amazon.com/organizations/)
- [AWS Identity and Access Management (IAM)](https://aws.amazon.com/iam/)
- [AWS CloudFormation](https://aws.amazon.com/cloudformation/)
- [AWS CLI (Command Line Interface)](https://aws.amazon.com/cli/)

---

# 1. Understanding the Why

In the book "GRC Engineering in AWS", it introduces the core idea that manual compliance is impossible in dynamic cloud environments. Instead, IaC + SCPs create a self-enforcing compliance system:

## CloudFormation (IaC)
- Deploys resources correctly by default
- Eliminates configuration drift
- Creates auditable change history
- Serves as evidence for auditors

## Service Control Policies
- Create organization-wide guardrails 
- Override IAM permissions, even admin users  
- Prevent misconfigurations or dangerous actions  
- Enforce compliance boundaries at scale

---

# 2. Requirements

The following are required in order to complete this project:

- AWS account
- IAM user account with appropriate permissions
- AWS Organizations enabled
- AWS CLI v2 installed 

---

# 3. Step 1: Discover Organization IDs

Before deploying, gather the required identifiers.

## Get Organization ID

The following command queries the AWS Organization ID:

```
aws organizations list-roots \
    --query "Roots[0].Id" \
    --output text
```

Example output:

```
r-abcd
```

## List OUs 

If applicable, this command will list all of the Organizational Units (OUs) in the Organization:

```
aws organizations list-organizational-units-for-parent \
    --parent-id <ROOT_ID> \
    --query "OrganizationalUnits[*].Id" \
    --output text
```

Example output:

```
ou-abcd-12345678 ou-abcd-87654321 ou-abcd-a1b2c3d4
```

---

# 4. Step 2: Deploy Service Control Policies (SCPs)

## Create a SCP

The following command deploys Service Control Policies (SCPs):

```
aws organizations create-policy \
    --content file://<SCP_FILENAME>.json \
    --name <SCP_NAME> \
    --description "<POLICY_DESCRIPTION>" \
    --type SERVICE_CONTROL_POLICY
```

Change the `<SCP_FILENAME>` and `<SCP_NAME>` to the appropriate SCP when deploying the policies.

Example output:

```
{
    "Policy": {
        "PolicySummary": {
            "Id": "p-0abc1234",
            "Arn": "arn:aws:organizations::123456789012:policy/service_control_policy/p-0abc1234",
            "Name": "SCP-DenyAuditLogDeletion",
            "Description": "Prevents the deletion of audit logs.",
            "Type": "SERVICE_CONTROL_POLICY",
            "AwsManaged": false
        },
        "Content": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"DenyAuditLogDeletion\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"cloudtrail:DeleteTrail\",\n        \"cloudtrail:StopLogging\"\n      ],\n      \"Resource\": \"*\"\n    }\n  ]\n}"
    }
}
```

Ensure to run the aforementioned command to deploy SCPs for all policies that need to be implemented for the organization.

## Capture Policy IDs

This command will output all SCPs that were deployed with ID and Name in a table format:

```
aws organizations list-policies \
    --filter SERVICE_CONTROL_POLICY \
    --query "Policies[].{Name:Name, Id:Id}" \
    --output table
```

Example output:

```
----------------------------------------------
|              ListPolicies                  |
----------------------------------------------
|     Name                     |     Id       |
|------------------------------|--------------|
|  SCP-DenyRootUserActions     |  p-1a2b3c4d  |
|  SCP-DenyAuditLogDeletion    |  p-5e6f7g8h  |
|  SCP-PreventOpenSSH          |  p-9j0k1l2m  |
----------------------------------------------
```

## Attach the SCP to Organization Root

This command must be done for each SCP that must be attached to the Organization Root.

```
aws organizations attach-policy \
    --policy-id <POLICY_ID> \
    --target-id <ROOT_ID>
```

The aforementioned command does not return any output in the terminal.

Once deployment of all SCPS is completed, the following command will show all SCPs attached to the Organization Root in a table format: 

```
aws organizations list-policies-for-target \
    --target-id <ROOT_ID> \
    --filter SERVICE_CONTROL_POLICY \
    --output table
```

Example output:

```
------------------------------------------------------
|              ListPoliciesForTarget                 |
------------------------------------------------------
|     Name                     |        Id           |
|----------------------------------------------------|
|  SCP-DenyRootUserActions     |  p-1a2b3c4d         |
|  SCP-DenyAuditLogDeletion    |  p-5e6f7g8h         |
------------------------------------------------------
```

---

# 5. Step 3: Deploy CloudFormation Template

The following command deploys a CloudFormation template:

```
aws cloudformation deploy \
    --stack-name <STACK_NAME> \
    --template-file <STACK_FILENAME.yaml> \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
    --parameter-overrides \
        OrganizationId=<YOUR_ORG_ID> \
        OrgRootId=<ORG_ROOT_ID> 
```

Example output:

```
Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - <BUCKET_NAME>
```

The following command checks the deployment status of the CloudFormation template:

```
aws cloudformation describe-stacks \
    --query "Stacks[*].StackName" \
    --output table
```

Example output:

```
---------------------------------
|     DescribeStacks            |
---------------------------------
|  <STACK_NAME>                 |
---------------------------------
```

---

# 6. Updating CloudFormation templates and SCPs

If anything needs to be updated, run the  following commands:

```
aws organizations update-policy \
    --policy-id <POLICY_ID> \
    --content file://<UPDATED_SCP>.json
```

```
aws cloudformation deploy \
    --stack-name <STACK_NAME> \
    --template-file <STACK_FILENAME>.yaml \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND
```

---

# 7. Resource Cleanup

The following command detachs all SCPs:

```
aws organizations detach-policy \
  --policy-id <POLICY_ID> \
  --target-id <ORG_ROOT_ID>
```

The following command deletes the CloudFormation stack:

```
aws cloudformation delete-stack \
  --stack-name <STACK_NAME>
```

Both commands do not return any output in the terminal.

---

# 9. Conclusion 

This project brings Chapter 5 of "GRC Engineering for AWS" to life by showing how compliance becomes something you build, not something you document.

## Key Takeaways

- **IaC = Compliant by Default**  
  CloudFormation removes drift, enforces secure configurations, and turns controls into repeatable deployments.

- **SCPs = Organizational Guardrails**  
  They override IAM, prevent risky actions, and ensure consistent boundaries across all accounts.

- **Defense in Depth Matters**  
  IaC deploys secure resources, SCPs prevent misconfigurations, and monitoring tools like Config/Security Hub maintain visibility.

- **Automation Beats Manual Review**  
  Codified controls reduce human error, increase speed, and create a self-enforcing compliance ecosystem.

- **Git Becomes Evidence**  
  Every change is tracked, versioned, and auditable.

## Final Thoughts

This project takes the core step that defines a GRC Engineer:  

**implementing controls as code.**

This foundation now enables you to expand into CI/CD guardrails, drift remediation, event-driven compliance checks, and full multi-account architectures.  

You're not just validating compliance anymore, you're engineering it.


---

# Resources

- [GRC Enginering for AWS by AJ Yawn](https://ajyawn.com/books)
- [GRC Enginering for AWS Chapter 5 Repository](https://github.com/ajy0127/thegrcengineeringbook/tree/master/chapter-5)