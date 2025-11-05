-- =============================================
-- FIX MISSING ROLES IN GROUP
-- =============================================
-- This script adds the missing roles (SupplierMasterIndex, StateMasterIndex, UnitMasterIndex)
-- to your group's ApplicationRoleGroups table
-- =============================================

-- Step 1: Find your group ID
-- Run this first and note the GroupId
-- Try different possible table names:

-- Option 1: Groups table
SELECT 
    Id AS GroupId,
    Name AS GroupName
FROM Groups
ORDER BY Name;

-- If above fails, try: SELECT Id, Name FROM ApplicationGroups ORDER BY Name;
-- If that fails, try: SELECT Id, Name FROM AspNetGroups ORDER BY Name;

-- COPY YOUR GROUP ID FROM ABOVE AND REPLACE IT BELOW!
DECLARE @GroupId INT = 1;  -- <<<< REPLACE WITH YOUR ACTUAL GROUP ID!

-- Step 2: Get the Role IDs for the three missing roles
DECLARE @SupplierRoleId NVARCHAR(128);
DECLARE @StateRoleId NVARCHAR(128);
DECLARE @UnitRoleId NVARCHAR(128);

SELECT @SupplierRoleId = Id FROM AspNetRoles WHERE Name = 'SupplierMasterIndex';
SELECT @StateRoleId = Id FROM AspNetRoles WHERE Name = 'StateMasterIndex';
SELECT @UnitRoleId = Id FROM AspNetRoles WHERE Name = 'UnitMasterIndex';

-- Display the IDs we found
SELECT 
    'SupplierMasterIndex' AS RoleName, 
    @SupplierRoleId AS RoleId
UNION ALL
SELECT 'StateMasterIndex', @StateRoleId
UNION ALL
SELECT 'UnitMasterIndex', @UnitRoleId;

-- Step 3: Check if these roles are already assigned to your group
SELECT 
    arg.GroupId,
    arg.RoleId,
    r.Name AS RoleName,
    'ALREADY EXISTS' AS Status
FROM ApplicationRoleGroups arg
INNER JOIN AspNetRoles r ON arg.RoleId = r.Id
WHERE arg.GroupId = @GroupId
  AND r.Name IN ('SupplierMasterIndex', 'StateMasterIndex', 'UnitMasterIndex');

-- Step 4: Add the missing roles to ApplicationRoleGroups
-- (Only if they don't already exist)

-- Add SupplierMasterIndex
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @SupplierRoleId)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@GroupId, @SupplierRoleId);
    PRINT 'Added SupplierMasterIndex to group';
END
ELSE
    PRINT 'SupplierMasterIndex already exists in group';

-- Add StateMasterIndex
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @StateRoleId)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@GroupId, @StateRoleId);
    PRINT 'Added StateMasterIndex to group';
END
ELSE
    PRINT 'StateMasterIndex already exists in group';

-- Add UnitMasterIndex
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @UnitRoleId)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@GroupId, @UnitRoleId);
    PRINT 'Added UnitMasterIndex to group';
END
ELSE
    PRINT 'UnitMasterIndex already exists in group';

-- Step 5: Verify the roles are now assigned
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

-- =============================================
-- INSTRUCTIONS:
-- 1. Run Step 1 to find your GroupId
-- 2. Replace @GroupId value with your actual group ID
-- 3. Run the entire script
-- 4. LOGOUT and LOGIN to refresh roles in session
-- 5. Check if the three menus appear
-- =============================================
