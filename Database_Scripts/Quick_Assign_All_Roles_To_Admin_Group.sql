-- =============================================
-- QUICK FIX: Assign ALL Menu Roles to Admin Group
-- =============================================
-- This script assigns all 84 roles to the "Admin" group
-- Adjust the @GroupName if your group has a different name
-- =============================================

DECLARE @GroupName NVARCHAR(256) = 'Admin'; -- Change this if your group name is different (e.g., 'SuperAdmin', 'Manager')
DECLARE @GroupId INT;

-- Get the Group ID
SELECT @GroupId = Id FROM Groups WHERE Name = @GroupName;

IF @GroupId IS NULL
BEGIN
    PRINT 'ERROR: Group "' + @GroupName + '" not found!';
    PRINT 'Available groups:';
    SELECT Name FROM Groups;
    RETURN;
END

PRINT 'Group "' + @GroupName + '" found with ID: ' + CAST(@GroupId AS NVARCHAR(10));
PRINT '';
PRINT 'Assigning roles to group...';

-- =============================================
-- CLEAR EXISTING MENU ROLES FROM GROUP (OPTIONAL)
-- =============================================
-- Uncomment if you want to clear old role assignments first
/*
DELETE FROM ApplicationRoleGroups 
WHERE GroupId = @GroupId 
AND RoleId IN (
    SELECT Id FROM AspNetRoles WHERE RMenuGroupId IN (1, 2, 3, 4)
);
PRINT 'Cleared existing menu roles from group.';
*/

-- =============================================
-- ASSIGN ALL TRANSACTION ROLES (GroupId = 1)
-- =============================================
INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
SELECT @GroupId, Id
FROM AspNetRoles
WHERE RMenuGroupId = 1
AND Id NOT IN (SELECT RoleId FROM ApplicationRoleGroups WHERE GroupId = @GroupId);

PRINT 'Assigned Transaction roles (12)';

-- =============================================
-- ASSIGN ALL TALLY ROLES (GroupId = 2)
-- =============================================
INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
SELECT @GroupId, Id
FROM AspNetRoles
WHERE RMenuGroupId = 2
AND Id NOT IN (SELECT RoleId FROM ApplicationRoleGroups WHERE GroupId = @GroupId);

PRINT 'Assigned Tally roles (4)';

-- =============================================
-- ASSIGN ALL REPORTS ROLES (GroupId = 3)
-- =============================================
INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
SELECT @GroupId, Id
FROM AspNetRoles
WHERE RMenuGroupId = 3
AND Id NOT IN (SELECT RoleId FROM ApplicationRoleGroups WHERE GroupId = @GroupId);

PRINT 'Assigned Reports roles (4)';

-- =============================================
-- ASSIGN ALL MASTERS ROLES (GroupId = 4)
-- =============================================
INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
SELECT @GroupId, Id
FROM AspNetRoles
WHERE RMenuGroupId = 4
AND Id NOT IN (SELECT RoleId FROM ApplicationRoleGroups WHERE GroupId = @GroupId);

PRINT 'Assigned Masters roles (64)';
PRINT '';

-- =============================================
-- VERIFICATION
-- =============================================
PRINT '============================================='
PRINT 'VERIFICATION: Roles assigned to group'
PRINT '============================================='

SELECT 
    CASE r.RMenuGroupId
        WHEN 1 THEN 'Transaction'
        WHEN 2 THEN 'Tally'
        WHEN 3 THEN 'Reports'
        WHEN 4 THEN 'Masters'
    END AS MenuName,
    COUNT(*) AS AssignedRoles
FROM ApplicationRoleGroups gr
INNER JOIN AspNetRoles r ON gr.RoleId = r.Id
WHERE gr.GroupId = @GroupId
AND r.RMenuGroupId IN (1, 2, 3, 4)
GROUP BY r.RMenuGroupId
ORDER BY r.RMenuGroupId;

PRINT '';
PRINT 'Total roles assigned to "' + @GroupName + '" group:';

SELECT COUNT(*) AS TotalRolesAssigned
FROM ApplicationRoleGroups gr
INNER JOIN AspNetRoles r ON gr.RoleId = r.Id
WHERE gr.GroupId = @GroupId
AND r.RMenuGroupId IN (1, 2, 3, 4);

PRINT '';
PRINT '============================================='
PRINT 'SETUP COMPLETE!'
PRINT '============================================='
PRINT 'All 84 menu roles have been assigned to the "' + @GroupName + '" group.';
PRINT '';
PRINT 'IMPORTANT: Users must LOGOUT and LOGIN again for changes to take effect!';
PRINT '============================================='
