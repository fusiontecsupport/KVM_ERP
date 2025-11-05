-- =============================================
-- FIX WRONG ROLE MAPPING FOR SUPERADMIN
-- =============================================
-- Problem: SuperAdmin has wrong roles mapped:
--   - SupplierMasterEdit (should be SupplierMasterIndex)
--   - PurchaseInvoiceApprovalPrint (should be StateMasterIndex)
--   - StockViewPrint (should be UnitMasterIndex)
-- 
-- This script:
--   1. Removes the wrong roles
--   2. Adds the correct Index roles
-- =============================================

DECLARE @GroupId INT = 1;  -- SuperAdmin

PRINT '========================================';
PRINT 'FIXING WRONG ROLE MAPPING FOR SUPERADMIN';
PRINT '========================================';

-- Step 1: Get IDs of WRONG roles to remove
DECLARE @SupplierMasterEdit NVARCHAR(128);
DECLARE @PurchaseInvoiceApprovalPrint NVARCHAR(128);
DECLARE @StockViewPrint NVARCHAR(128);

SELECT @SupplierMasterEdit = Id FROM AspNetRoles WHERE Name = 'SupplierMasterEdit';
SELECT @PurchaseInvoiceApprovalPrint = Id FROM AspNetRoles WHERE Name = 'PurchaseInvoiceApprovalPrint';
SELECT @StockViewPrint = Id FROM AspNetRoles WHERE Name = 'StockViewPrint';

-- Step 2: Get IDs of CORRECT roles to add
DECLARE @SupplierMasterIndex NVARCHAR(128);
DECLARE @StateMasterIndex NVARCHAR(128);
DECLARE @UnitMasterIndex NVARCHAR(128);

SELECT @SupplierMasterIndex = Id FROM AspNetRoles WHERE Name = 'SupplierMasterIndex';
SELECT @StateMasterIndex = Id FROM AspNetRoles WHERE Name = 'StateMasterIndex';
SELECT @UnitMasterIndex = Id FROM AspNetRoles WHERE Name = 'UnitMasterIndex';

PRINT '';
PRINT 'Step 1: REMOVING WRONG ROLES...';
PRINT '========================================';

-- Remove SupplierMasterEdit (wrong)
IF EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @SupplierMasterEdit)
BEGIN
    DELETE FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @SupplierMasterEdit;
    PRINT '✓ Removed: SupplierMasterEdit';
END
ELSE
    PRINT '○ Not found: SupplierMasterEdit';

-- Remove PurchaseInvoiceApprovalPrint (wrong)
IF EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @PurchaseInvoiceApprovalPrint)
BEGIN
    DELETE FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @PurchaseInvoiceApprovalPrint;
    PRINT '✓ Removed: PurchaseInvoiceApprovalPrint';
END
ELSE
    PRINT '○ Not found: PurchaseInvoiceApprovalPrint';

-- Remove StockViewPrint (wrong)
IF EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @StockViewPrint)
BEGIN
    DELETE FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @StockViewPrint;
    PRINT '✓ Removed: StockViewPrint';
END
ELSE
    PRINT '○ Not found: StockViewPrint';

PRINT '';
PRINT 'Step 2: ADDING CORRECT INDEX ROLES...';
PRINT '========================================';

-- Add SupplierMasterIndex (correct)
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @SupplierMasterIndex)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@GroupId, @SupplierMasterIndex);
    PRINT '✓ Added: SupplierMasterIndex';
END
ELSE
    PRINT '○ Already exists: SupplierMasterIndex';

-- Add StateMasterIndex (correct)
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @StateMasterIndex)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@GroupId, @StateMasterIndex);
    PRINT '✓ Added: StateMasterIndex';
END
ELSE
    PRINT '○ Already exists: StateMasterIndex';

-- Add UnitMasterIndex (correct)
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @GroupId AND RoleId = @UnitMasterIndex)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@GroupId, @UnitMasterIndex);
    PRINT '✓ Added: UnitMasterIndex';
END
ELSE
    PRINT '○ Already exists: UnitMasterIndex';

PRINT '';
PRINT 'Step 3: VERIFICATION';
PRINT '========================================';

-- Verify the correct roles are now assigned
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

PRINT '';
PRINT '========================================';
PRINT '✅ Done! Wrong roles removed, correct roles added.';
PRINT '⚠️  Now LOGOUT and LOGIN to refresh roles in session.';
PRINT '';
PRINT 'Expected: All 3 menus should now appear:';
PRINT '  ✓ Supplier Master';
PRINT '  ✓ State Master';
PRINT '  ✓ Unit Master';
PRINT '========================================';
