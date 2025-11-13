I'll help you enhance principals.go with all these features. Let me start by reading the current code and your notes to understand the full scope.

Read
/home/user/test2/azure/commands/principals.go
Read 454 lines
Glob
tmp/principals*
Glob
tmp/*rbac*
Read
/home/user/test2/tmp/principals and rbac enumeration notes
Read 133 lines
Read
/home/user/test2/internal/azure/principal_helpers.go
Read 1,924 lines
Read
/home/user/test2/internal/azure/account_helpers.go
Read 200 lines
Now let me create a comprehensive plan for updating principals.go with all the enhancements you've requested.

Update Todos
 Reviewing requirements and creating implementation plan
 Add PIM (Privileged Identity Management) support - Eligible and Active roles
 Add Conditional Access Policies column to principals output
 Enhance RBAC to check Tenant Root (/) and Management Group hierarchy
 Add Inherited Permissions column showing inheritance chain
 Add security groups as rows in principal enumeration
 Add Groups (membership) column after Object ID
 Create IsPrincipalAdmin function for managed identity admin role checking
 Update module headers to reflect new columns
 Test the enhanced principals command
 Commit and push changes to feature branch
Based on your requirements and the notes, here's my comprehensive plan for enhancing principals.go:

Implementation Plan
Current State Analysis
✅ Enumerates Users, Service Principals, and Managed Identities
✅ Shows RBAC roles at subscription level
✅ Shows Graph API permissions and OAuth2 grants
❌ Missing PIM information
❌ Missing Conditional Access Policies
❌ Missing Tenant Root and Management Group scope checking
❌ Missing inherited permissions tracking
❌ Missing groups as principals
❌ Missing group membership column
❌ Missing admin role indicator
Features to Implement
1. PIM (Privileged Identity Management)

Add PIM Eligible roles (can be activated)
Add PIM Active roles (currently activated)
Show attribution: Direct vs Group-based
Format: Display next to RBAC role (e.g., "Owner (PIM Active - Group)")
2. Conditional Access Policies

New column showing CA policies assigned to each principal
Query: /identity/conditionalAccess/policies via Graph API
3. Enhanced RBAC Scope Coverage

Add Tenant Root (/) scope checking
Add Management Group hierarchy checking (using existing GetManagementGroupHierarchy)
Currently only checking subscription scope
4. Inherited Permissions

New column tracking inheritance chain
Show: Management Group → Subscription → Resource Group → Resource
Display which scope the permission originates from
5. Groups as Principals

Enumerate security groups via Graph API
Add groups as rows with their RBAC roles and permissions
Include nested group memberships
6. Group Membership Column

Use existing GetUserGroupMemberships function
New column after "Object ID" showing groups each principal belongs to
Format: Display group names (not just IDs)
7. Admin Role Indicator Function

Create IsPrincipalAdmin() helper function for other modules
Check for admin roles: Global Admin, Privileged Role Admin, Owner, Contributor, User Access Administrator, etc.
Export for use in managed identity modules
Updated Column Structure
1. Tenant/Subscription Context
2. Source Service
3. Principal Type
4. User Principal Name / App ID
5. Display Name
6. Object ID
7. Groups (NEW) - group memberships
8. RBAC Roles (with PIM status)
9. PIM Status (NEW) - Eligible/Active with attribution
10. Inherited Permissions (NEW) - inheritance chain
11. Conditional Access Policies (NEW)
12. Graph API Permissions
13. Delegated OAuth2 Grants
Regarding Conditional Access: I recommend keeping it in principals.go since CA policies are directly tied to principals (users/service principals/groups). However, we could also create a dedicated policies.go module later if needed.

Subscription Reader Role: The web portal shows your Reader role on subscriptions - we'll capture this by checking all RBAC scopes (Tenant Root, Management Groups, and Subscriptions).

Should I proceed with this implementation?