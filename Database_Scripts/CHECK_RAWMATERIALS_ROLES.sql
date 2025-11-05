-- =============================================
-- CHECK RAW MATERIALS ROLES MAPPING
-- =============================================
-- This script checks all RawMaterial-related roles
-- and their assignments to groups
-- =============================================

PRINT '========================================';
PRINT 'STEP 1: ALL RAW MATERIAL ROLES IN DATABASE';
PRINT '========================================';

-- Find all RawMaterial* roles
SELECT 
    Id,
    Name,
    Description,
    Discriminator
FROM AspNetRoles
WHERE Name LIKE '%RawMaterial%'
ORDER BY Name;

PRINT '';
PRINT '========================================';
PRINT 'STEP 2: RAW MATERIALS ROLES ASSIGNED TO GROUPS';
PRINT '========================================';

-- Check which groups have RawMaterial* roles
SELECT 
    arg.GroupId,
    g.Name AS GroupName,
    r.Name AS RoleName,
    r.Description
FROM ApplicationRoleGroups arg
INNER JOIN Groups g ON arg.GroupId = g.Id
INNER JOIN AspNetRoles r ON arg.RoleId = r.Id
WHERE r.Name LIKE '%RawMaterial%'
ORDER BY arg.GroupId, r.Name;

PRINT '';
PRINT '========================================';
PRINT 'STEP 3: SPECIFIC CHECK FOR RAWMATERIALSINTAKEINDEX';
PRINT '========================================';

-- Check if RawMaterialsIntakeIndex exists
DECLARE @RoleId NVARCHAR(128);
SELECT @RoleId = Id FROM AspNetRoles WHERE Name = 'RawMaterialsIntakeIndex';

IF @RoleId IS NOT NULL
BEGIN
    PRINT '✅ Role EXISTS in AspNetRoles';
    PRINT 'Role ID: ' + @RoleId;
    
    -- Check which groups have it
    SELECT 
        arg.GroupId,
        g.Name AS GroupName,
        'RawMaterialsIntakeIndex' AS RoleName
    FROM ApplicationRoleGroups arg
    INNER JOIN Groups g ON arg.GroupId = g.Id
    WHERE arg.RoleId = @RoleId;
    
    IF @@ROWCOUNT = 0
    BEGIN
        PRINT '⚠️  WARNING: RawMaterialsIntakeIndex exists but is NOT assigned to ANY group!';
    END
END
ELSE
BEGIN
    PRINT '❌ ERROR: RawMaterialsIntakeIndex does NOT exist in AspNetRoles table!';
    PRINT 'You need to run: Insert_Transaction_Menu_Roles.sql';
END

PRINT '';
PRINT '========================================';
PRINT 'STEP 4: SUMMARY BY GROUP';
PRINT '========================================';

-- Count RawMaterial roles per group
SELECT 
    g.Id AS GroupId,
    g.Name AS GroupName,
    COUNT(r.Id) AS RawMaterialRoleCount
FROM Groups g
LEFT JOIN ApplicationRoleGroups arg ON g.Id = arg.GroupId
LEFT JOIN AspNetRoles r ON arg.RoleId = r.Id AND r.Name LIKE '%RawMaterial%'
GROUP BY g.Id, g.Name
ORDER BY g.Id;

PRINT '';
PRINT '========================================';
PRINT 'DIAGNOSTIC COMPLETE';
PRINT '========================================';
