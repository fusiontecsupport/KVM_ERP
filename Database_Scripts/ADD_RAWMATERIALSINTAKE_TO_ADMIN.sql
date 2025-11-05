-- =============================================
-- ADD RAWMATERIALSINTAKEINDEX TO ADMIN
-- =============================================
-- This ensures RawMaterialsIntakeIndex is assigned to Admin group
-- Run this if the role exists but is not showing in the frontend
-- =============================================

DECLARE @GroupId INT = 2;  -- Admin (change to 1 for SuperAdmin)

PRINT '========================================';
PRINT 'ADDING RAWMATERIALSINTAKEINDEX TO ADMIN';
PRINT '========================================';

-- Get the role ID
DECLARE @RoleId NVARCHAR(128);
SELECT @RoleId = Id FROM AspNetRoles WHERE Name = 'RawMaterialsIntakeIndex';

IF @RoleId IS NULL
BEGIN
    PRINT '❌ ERROR: RawMaterialsIntakeIndex role does not exist!';
    PRINT 'Please run: Insert_Transaction_Menu_Roles.sql first';
END
ELSE
BEGIN
    PRINT '✅ Found RawMaterialsIntakeIndex role: ' + @RoleId;
    
    -- Check if already assigned
    IF EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @RoleId)
    BEGIN
        PRINT '○ Already assigned to Admin group';
    END
    ELSE
    BEGIN
        -- Add to Admin group
        INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
        VALUES (@GroupId, @RoleId);
        
        PRINT '✅ Added RawMaterialsIntakeIndex to Admin group';
    END
    
    -- Verify
    PRINT '';
    PRINT 'Verification:';
    SELECT 
        arg.GroupId,
        g.Name AS GroupName,
        r.Name AS RoleName,
        r.Description
    FROM ApplicationRoleGroups arg
    INNER JOIN Groups g ON arg.GroupId = g.Id
    INNER JOIN AspNetRoles r ON arg.RoleId = r.Id
    WHERE arg.GroupId = @GroupId
      AND r.Name = 'RawMaterialsIntakeIndex';
END

PRINT '';
PRINT '========================================';
PRINT '✅ Done!';
PRINT '⚠️  Now LOGOUT and LOGIN to refresh roles.';
PRINT '========================================';
