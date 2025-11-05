-- Check which table stores group-role assignments

-- Option 1: ApplicationRoleGroups table
SELECT TOP 10
    'ApplicationRoleGroups' AS TableName,
    arg.GroupId,
    arg.RoleId,
    r.Name AS RoleName
FROM ApplicationRoleGroups arg
INNER JOIN AspNetRoles r ON arg.RoleId = r.Id
WHERE r.Name IN ('SupplierMasterIndex', 'StateMasterIndex', 'UnitMasterIndex');

-- Option 2: GroupRoleMaster table (if it exists)
SELECT TOP 10
    'GroupRoleMaster' AS TableName,
    grm.GroupId,
    grm.RoleId,
    r.Name AS RoleName
FROM GroupRoleMaster grm
INNER JOIN AspNetRoles r ON grm.RoleId = r.Id
WHERE r.Name IN ('SupplierMasterIndex', 'StateMasterIndex', 'UnitMasterIndex');

-- Check what table has data
SELECT 'ApplicationRoleGroups' AS TableName, COUNT(*) AS RowCount FROM ApplicationRoleGroups
UNION ALL
SELECT 'GroupRoleMaster', COUNT(*) FROM GroupRoleMaster;

-- THIS WILL TELL US WHICH TABLE IS BEING USED!
