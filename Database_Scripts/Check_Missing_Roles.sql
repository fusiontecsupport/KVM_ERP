-- Check if the three missing menu roles exist in the database

SELECT 
    Name AS RoleName,
    Description,
    RMenuType AS MenuName,
    RControllerName AS Controller
FROM AspNetRoles
WHERE Name IN (
    'SupplierMasterIndex',
    'StateMasterIndex', 
    'UnitMasterIndex'
)
ORDER BY Name;

-- If no results, then these roles don't exist!
-- Expected: 3 rows

-- Also check what roles the current user has for these controllers
SELECT 
    r.Name AS RoleName,
    r.RMenuType AS MenuName,
    r.RControllerName AS Controller
FROM AspNetRoles r
WHERE r.RControllerName IN ('SupplierMaster', 'StateMaster', 'UnitMaster')
ORDER BY r.RControllerName, r.Name;

-- This should show ALL roles for these 3 masters (Index, Create, Edit, Delete)
