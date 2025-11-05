-- Check if the roles are actually assigned to the group

-- Step 1: Find the group ID (replace 'YourGroupName' with your actual group name)
-- Common group names: 'Admin', 'User', 'Manager', etc.
SELECT 
    Id AS GroupId, 
    Name AS GroupName
FROM AspNetRoles
WHERE Discriminator = 'ApplicationRole' 
  AND Name NOT LIKE '%Master%'  -- Exclude menu roles
ORDER BY Name;

-- Step 2: Check role assignments for a specific group
-- Replace @GroupId with the actual GroupId from Step 1
DECLARE @GroupId NVARCHAR(128) = 'YOUR_GROUP_ID_HERE';  -- REPLACE THIS!

SELECT 
    r.Name AS RoleName,
    r.RMenuType AS MenuName,
    r.RControllerName AS Controller,
    CASE WHEN grm.RoleId IS NOT NULL THEN 'ASSIGNED' ELSE 'NOT ASSIGNED' END AS AssignmentStatus
FROM AspNetRoles r
LEFT JOIN GroupRoleMaster grm ON r.Id = grm.RoleId AND grm.GroupId = @GroupId
WHERE r.Name IN ('SupplierMasterIndex', 'StateMasterIndex', 'UnitMasterIndex')
ORDER BY r.Name;

-- Step 3: Check what roles ARE assigned to the group
SELECT 
    r.Name AS AssignedRole,
    r.RMenuType AS MenuName,
    r.RControllerName AS Controller
FROM GroupRoleMaster grm
INNER JOIN AspNetRoles r ON grm.RoleId = r.Id
WHERE grm.GroupId = @GroupId
  AND r.RControllerName IN ('SupplierMaster', 'StateMaster', 'UnitMaster')
ORDER BY r.RControllerName, r.Name;

-- Expected: Should show which roles are assigned and which are missing
