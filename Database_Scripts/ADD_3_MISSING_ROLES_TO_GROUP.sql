-- =============================================
-- ADD 3 MISSING ROLES TO SuperAdmin GROUP
-- =============================================
-- This adds SupplierMasterIndex, StateMasterIndex, UnitMasterIndex 
-- to ApplicationRoleGroups for SuperAdmin group (GroupId = 1)
-- =============================================

-- Step 1: Get the Role IDs
DECLARE @SupplierRoleId NVARCHAR(128);
DECLARE @StateRoleId NVARCHAR(128);
DECLARE @UnitRoleId NVARCHAR(128);

SELECT @SupplierRoleId = Id FROM AspNetRoles WHERE Name = 'SupplierMasterIndex';
SELECT @StateRoleId = Id FROM AspNetRoles WHERE Name = 'StateMasterIndex';
SELECT @UnitRoleId = Id FROM AspNetRoles WHERE Name = 'UnitMasterIndex';

-- Display what we found
SELECT 'SupplierMasterIndex' AS RoleName, @SupplierRoleId AS RoleId
UNION ALL
SELECT 'StateMasterIndex', @StateRoleId
UNION ALL
SELECT 'UnitMasterIndex', @UnitRoleId;

-- Step 2: Add to ApplicationRoleGroups for GroupId = 2 (Admin)
DECLARE @GroupId INT = 2;  -- Admin (change to 1 for SuperAdmin, 3 for Manager, 4 for Users)

-- Add SupplierMasterIndex
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @SupplierRoleId)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@GroupId, @SupplierRoleId);
    PRINT 'Added SupplierMasterIndex to Admin group';
END
ELSE
    PRINT 'SupplierMasterIndex already exists in Admin group';

-- Add StateMasterIndex
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @StateRoleId)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@GroupId, @StateRoleId);
    PRINT 'Added StateMasterIndex to Admin group';
END
ELSE
    PRINT 'StateMasterIndex already exists in Admin group';

-- Add UnitMasterIndex
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @UnitRoleId)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@GroupId, @UnitRoleId);
    PRINT 'Added UnitMasterIndex to Admin group';
END
ELSE
    PRINT 'UnitMasterIndex already exists in Admin group';

-- Step 3: Verify they were added
SELECT 
    arg.GroupId,
    g.Name AS GroupName,
    r.Name AS RoleName,
    r.Description
FROM ApplicationRoleGroups arg
INNER JOIN Groups g ON arg.GroupId = g.Id
INNER JOIN AspNetRoles r ON arg.RoleId = r.Id
WHERE arg.GroupId = @GroupId
  AND r.Name IN ('SupplierMasterIndex', 'StateMasterIndex', 'UnitMasterIndex')
ORDER BY r.Name;

-- Expected: 3 rows showing all 3 roles assigned to Admin
PRINT '✅ Done! Now LOGOUT and LOGIN to refresh roles in session.';
