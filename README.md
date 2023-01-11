# :fox_face: CloudFox :fox_face:
CloudFox helps you gain situational awareness in unfamiliar cloud environments. It’s an open source command line tool created to help penetration testers and other offensive security professionals find exploitable attack paths in cloud infrastructure. 

#### CloudFox helps you answer the following common questions (and many more): 

* What regions is this AWS account using and roughly how many resources are in the account?
* What secrets are lurking in EC2 userdata or service specific environment variables?
* What workloads have administrative permissions attached?  
* What actions/permissions does this [principal] have?
* What role trusts are overly permissive or allow cross-account assumption?
* What endpoints/hostnames/IPs can I attack from an external starting point (public internet)?
* What endpoints/hostnames/IPs can I attack from an internal starting point (assumed breach within the VPC)?
* What filesystems can I potentially mount from a compromised resource inside the VPC?

## Demos, Examples, Walkthroughs
* [Blog - Introducing: CloudFox](https://bishopfox.com/blog/introducing-cloudfox)
* [Video - CloudFox Intro Demos](https://www.youtube.com/watch?v=ReWoUgpUuiQ)
* [Video - Tool Talk: CloudFox AWS sub-command walkthroughs](https://youtu.be/KKsYfL5uVU4?t=360) 

## Quick Start
CloudFox is modular (you can run one command at a time), but there is an `aws all-checks` command that will run the other aws commands for you with sane defaults: 

`cloudfox aws --profile [profile-name] all-checks`

![](/.github/images/cloudfox-output-p1.png)
![](/.github/images/cloudfox-output-p2.png)

### White Box Enumeration
CloudFox was designed to be executed by a principal with limited read-only permissions, but it's purpose is to help you find attack paths that can be exploited in simulated compromise scenarios (aka, objective based penetration testing). 

### Black Box Enumeration 
CloudFox can be with "found" credentials, similar to how you would use [weirdAAL](https://github.com/carnal0wnage/weirdAAL) or [enumerate-iam](https://github.com/andresriancho/enumerate-iam). Checks that fail, do so silently, so any data returned means your "found" creds have the access needed to retrieve it.   

For the full documentation please refer to our [wiki](https://github.com/BishopFox/CloudFox/wiki).


## Supported Cloud Providers

| Provider| CloudFox Commands |
| - | - |
| AWS | 23 | 
| Azure | 4 | 
| GCP | Support Planned |
| Kubernetes | Support Planned | 


# Install

**Option 1:** Download the [latest binary release](https://github.com/BishopFox/cloudfox/releases) for your platform.

**Option 2:** [Install Go](https://golang.org/doc/install), clone the CloudFox repository and compile from source
   ```
   # git clone https://github.com/BishopFox/cloudfox.git
   ...omitted for brevity...
   # cd ./cloudfox
   # go build .
   # ./cloudfox
   ```

# Prerequisites


### AWS
* AWS CLI installed
* Supports AWS profiles, AWS environment variables, or metadata retrieval (on an ec2 instance)
   * To run commands on multiple profiles at once, you can specify the path to a file with a list of profile names seperated by a new line using the `-l` flag or pass all stored profiles with the `-a` flag.
* A principal with one recommended policies attached (described below)
* Recommended attached policies: **`SecurityAudit` + [CloudFox custom policy](./misc/aws/cloudfox-policy.json)** 

Additional policy notes (as of 09/2022):    

| Policy | Notes | 
| - | - |
| [CloudFox custom policy](./misc/aws/cloudfox-policy.json) | Has a complete list of every permission cloudfox uses and nothing else |
|  `arn:aws:iam::aws:policy/SecurityAudit` | Covers most cloudfox checks but is missing newer services or permissions like apprunner:\*, grafana:\*, lambda:GetFunctionURL, lightsail:GetContainerServices |
|  `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess` | Covers most cloudfox checks but is missing newer services or permissions like AppRunner:\*, grafana:\*, lambda:GetFunctionURL, lightsail:GetContainerServices - and is also missing iam:SimulatePrincipalPolicy. 
|  `arn:aws:iam::aws:policy/ReadOnlyAccess` | Only missing AppRunner, but also grants things like "s3:Get*" which can be overly permissive. |
|  `arn:aws:iam::aws:policy/AdministratorAccess` | This will work just fine with CloudFox, but if you were handed this level of access as a penetration tester, that should probably be a finding in itself :) |

### Azure
* Viewer or similar permissions applied. 

# AWS Commands
| Provider | Command Name | Description 
| - | - | - | 
| AWS | [all-checks](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#all-checks) | Run all of the other commands using reasonable defaults. You'll  still want to check out the non-default options of each command, but this is a great place to start.  |
| AWS | [access-keys](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#access-keys) | Lists active access keys for all users. Useful for cross referencing a key you found with which in-scope account it belongs to.  |
| AWS | [buckets](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#filesystems)  | Lists the buckets in the account and gives you handy commands for inspecting them further.  |
| AWS | [cloudformation](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#cloudformation)  | Lists the cloudformation stacks in the account. Generates loot file with stack details, stack parameters, and stack output - look for secrets. |
| AWS | [ecr](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#ecr) | List the most recently pushed image URI from all repositories. Use the loot file to pull selected images down with docker/nerdctl for inspection. |
| AWS | [ecs-tasks](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#ecs-tasks) | List all ecs tasks. This returns a list of ecs tasks and associated cluster, task definition, container instance, launch type, and associated IAM principal. |
| AWS | [eks](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#eks) | List all EKS clusters, see if they expose their endpoint publicly, and check the associated IAM roles attached to reach cluster or node group. Generates a loot file with the `aws eks udpate-kubeconfig` command needed to connect to each cluster. |
| AWS | [elastic-network-interfaces](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#eni) | List all eni information. This returns a list of eni ID, type, external IP, private IP, VPCID, attached instance and a description. |
| AWS | [endpoints](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#endpoints) | Enumerates endpoints from various services. Scan these endpoints from both an internal and external position to look for things that don't require authentication, are misconfigured, etc. |
| AWS | [env-vars](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#env-vars) | Grabs the environment variables from services that have them (App Runner, ECS, Lambda, Lightsail containers, Sagemaker are supported. If you find a sensitive secret, use `cloudfox iam-simulator` AND `pmapper` to see who has access to them. |
| AWS | [filesystems](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#filesystems)  |  Enumerate the EFS and FSx filesystems that you might be able to mount without creds (if you have the right network access). For example, this is useful when you have `ec:RunInstance` but not `iam:PassRole`.  |
| AWS | [iam-simulator](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#iam-simulator) | Like pmapper, but uses the IAM policy simulator. It uses AWS's evaluation logic, but notably, it doesn't consider transitive access via privesc, which is why you should also always also use pmapper.   |
| AWS | [instances](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#instances) | Enumerates useful information for EC2 Instances in all regions like name, public/private IPs, and instance profiles. Generates loot files you can feed to nmap and other tools for service enumeration.  |
| AWS | [inventory](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#inventory) | Gain a rough understanding of size of the account and preferred regions.  |
| AWS | [lambda](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#lambda)  | Lists the lambda functions in the account, including which one's have admin roles attached. Also gives you handy commands for downloading each function.  |
| AWS | [outbound-assumed-roles](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#outbound-assumed-roles)  |  List the roles that have been assumed by principals in this account. This is an excellent way to find outbound attack paths that lead into other accounts. |
| AWS | [permissions](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#permissions) | Enumerates IAM permissions associated with all users and roles. Grep this output to figure out what permissions a particular principal has rather than logging into the AWS console and painstakingly expanding each policy attached to the principal you are investigating. |
| AWS | [principals](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#principals) | Enumerates IAM users and Roles so you have the data at your fingertips. |
| AWS | [pmapper](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#pmapper) | Looks for pmapper data stored on the local filesystem, [in the locations defined here](https://github.com/nccgroup/PMapper/wiki/Frequently-Asked-Questions#where-does-pmapper-store-its-data). If pmapper data has been found (you already ran `pmapper graph create`), then this command will use this data to build a graph in cloudfox memory let you know who can privesc to admin. 
| AWS | [principals](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#principals) | Enumerates IAM users and Roles so you have the data at your fingertips. |
| AWS | [ram](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#ram) | List all resources in this account that are shared with other accounts, or resources from other accounts that are shared with this account. Useful for cross-account attack paths. |
| AWS | [role-trusts](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#role-trusts) | Enumerates IAM role trust policies so you can look for overly permissive role trusts or find roles that trust a specific service. |
| AWS | [route53](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#route53) | Enumerate all records from all route53 managed zones. Use this for application and service enumeration. |
| AWS | [secrets](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#secrets) | List secrets from SecretsManager and SSM. Look for interesting secrets in the list and then see who has access to them using use `cloudfox iam-simulator` and/or `pmapper`. |
| AWS | [tags](https://github.com/BishopFox/cloudfox/wiki/AWS-Commands#tags) | List all resources with tags, and all of the tags. This can be used similar to inventory as another method to identify what types of resources exist in an account. |


# Azure Commands
| Provider | Command Name | Description 
| - | - | - | 
| Azure | [whoami](https://github.com/BishopFox/cloudfox/wiki/Azure-Commands#whoami) | Displays information on the tenant, subscriptions and resource groups available to your current Azure CLI session. This is useful to provide situation awareness on what tenant and subscription IDs to use with the other sub commands. | 
| Azure | [instances](https://github.com/BishopFox/cloudfox/wiki/Azure-Commands#instances) | Enumerates useful information for Compute instances in all available resource groups and subscriptions | 
| Azure | [rbac](https://github.com/BishopFox/cloudfox/wiki/Azure-Commands#rbac) | Lists Azure RBAC role assignments at subscription or tenant level |
| Azure | [storage](https://github.com/BishopFox/cloudfox/wiki/Azure-Commands#storage) | The storage command is still under development. Currently it only displays limited data about the storage accounts | 

# Authors
* [Carlos Vendramini](https://github.com/carlosvendramini-bf)
* [Seth Art (@sethsec](https://twitter.com/sethsec))

# Contributing
[Wiki - How to Contribute](https://github.com/BishopFox/cloudfox/wiki#how-to-contribute)

# TODO
* AWS - Add support for GovCloud and China regions

# FAQ

**How does CloudFox compare with ScoutSuite, Prowler, Steampipe's AWS Compliance Module, AWS Security Hub, etc.**

CloudFox doesn't create any alerts or findings, and doesn't check your environment for compliance to a baseline or benchmark. Instead, it simply enables you to be more efficient during your manual penetration testing activities. If gives you the information you'll likely need to validate whether an attack path is possible or not. 

**Why do I see errors in some CloudFox commands?**

* Services that don't exist in all regions - CloudFox tries a few ways to figure out what services are supported in each region. However some services don't support the methods CloudFox uses, so CloudFox defaults to just asking every region about the service. Regions that don't suppor the service will return errors. 
* You don't have permission - Another reason you might see errors if you don't have permissions to make calls that CloudFox is making. Either because the policy doesn't allow it (e.g., SecurityAudit doesn't allow all of the permissions CloudFox needs. Or, it might be an SCP that is blocking you.  

You can always look in the ~/.cloudfox/cloudfox-error.log file to get more information on errors. 

# Prior work and other related projects 
* [SmogCloud](https://github.com/BishopFox/smogcloud) - Inspiration for the `endpoints` command
* [SummitRoute's AWS Exposable Resources](https://github.com/SummitRoute/aws_exposable_resources)  - Inspiration for the `endpoints` command
* [Steampipe](https://steampipe.io/) - We used steampipe to prototype many cloudfox commands. While CloudFox is laser focused on helping cloud penetration testers, steampipe is an easy way to query any and all of your cloud resources. 
* [Principal Mapper](https://github.com/nccgroup/PMapper) - Inspiration for, and a strongly recommended partner to the `iam-simulator` command
* [Cloudsplaining](https://github.com/salesforce/cloudsplaining) - Inspiration for the `permissions` command
* [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Excellent cloud security benchmark tool. Provided inspiration for the `--userdata` functionality in the `instances` command, the `permissions` command, and many others
* [Prowler](https://github.com/prowler-cloud/prowler) - Another excellent cloud security benchmark tool. 
* [Pacu](https://github.com/RhinoSecurityLabs/pacu) - Excellent cloud penetration testing tool. PACU has quite a few enumeration commands similar to CloudFox, and lots of other commands that automate exploitation tasks (something that CloudFox avoids by design) 
 * [CloudMapper](https://github.com/duo-labs/cloudmapper) - Inspiration for the `inventory` command and just generally CloudFox as a whole 
