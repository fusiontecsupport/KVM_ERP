-- =============================================
-- FIX WRONG ROLE MAPPING FOR BOTH SUPERADMIN AND ADMIN
-- =============================================
-- Problem: Both SuperAdmin and Admin have wrong roles mapped:
--   - SupplierMasterEdit (should be SupplierMasterIndex)
--   - PurchaseInvoiceApprovalPrint (should be StateMasterIndex)
--   - StockViewPrint (should be UnitMasterIndex)
-- 
-- This script:
--   1. Removes the wrong roles from both groups
--   2. Adds the correct Index roles to both groups
-- =============================================

PRINT '========================================';
PRINT 'FIXING WRONG ROLE MAPPING';
PRINT 'FOR BOTH SUPERADMIN AND ADMIN';
PRINT '========================================';

-- Get IDs of WRONG roles to remove
DECLARE @SupplierMasterEdit NVARCHAR(128);
DECLARE @PurchaseInvoiceApprovalPrint NVARCHAR(128);
DECLARE @StockViewPrint NVARCHAR(128);

SELECT @SupplierMasterEdit = Id FROM AspNetRoles WHERE Name = 'SupplierMasterEdit';
SELECT @PurchaseInvoiceApprovalPrint = Id FROM AspNetRoles WHERE Name = 'PurchaseInvoiceApprovalPrint';
SELECT @StockViewPrint = Id FROM AspNetRoles WHERE Name = 'StockViewPrint';

-- Get IDs of CORRECT roles to add
DECLARE @SupplierMasterIndex NVARCHAR(128);
DECLARE @StateMasterIndex NVARCHAR(128);
DECLARE @UnitMasterIndex NVARCHAR(128);

SELECT @SupplierMasterIndex = Id FROM AspNetRoles WHERE Name = 'SupplierMasterIndex';
SELECT @StateMasterIndex = Id FROM AspNetRoles WHERE Name = 'StateMasterIndex';
SELECT @UnitMasterIndex = Id FROM AspNetRoles WHERE Name = 'UnitMasterIndex';

-- =============================================
-- FIX SUPERADMIN (GroupId = 1)
-- =============================================
DECLARE @SuperAdminGroupId INT = 1;

PRINT '';
PRINT '========================================';
PRINT 'FIXING SUPERADMIN (GroupId = 1)';
PRINT '========================================';
PRINT '';
PRINT 'Step 1: REMOVING WRONG ROLES...';
PRINT '----------------------------------------';

-- Remove wrong roles from SuperAdmin
IF EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @SuperAdminGroupId AND RoleId = @SupplierMasterEdit)
BEGIN
    DELETE FROM ApplicationRoleGroups WHERE GroupId = @SuperAdminGroupId AND RoleId = @SupplierMasterEdit;
    PRINT '✓ Removed: SupplierMasterEdit';
END
ELSE
    PRINT '○ Not found: SupplierMasterEdit';

IF EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @SuperAdminGroupId AND RoleId = @PurchaseInvoiceApprovalPrint)
BEGIN
    DELETE FROM ApplicationRoleGroups WHERE GroupId = @SuperAdminGroupId AND RoleId = @PurchaseInvoiceApprovalPrint;
    PRINT '✓ Removed: PurchaseInvoiceApprovalPrint';
END
ELSE
    PRINT '○ Not found: PurchaseInvoiceApprovalPrint';

IF EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @SuperAdminGroupId AND RoleId = @StockViewPrint)
BEGIN
    DELETE FROM ApplicationRoleGroups WHERE GroupId = @SuperAdminGroupId AND RoleId = @StockViewPrint;
    PRINT '✓ Removed: StockViewPrint';
END
ELSE
    PRINT '○ Not found: StockViewPrint';

PRINT '';
PRINT 'Step 2: ADDING CORRECT INDEX ROLES...';
PRINT '----------------------------------------';

-- Add correct roles to SuperAdmin
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @SuperAdminGroupId AND RoleId = @SupplierMasterIndex)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId) VALUES (@SuperAdminGroupId, @SupplierMasterIndex);
    PRINT '✓ Added: SupplierMasterIndex';
END
ELSE
    PRINT '○ Already exists: SupplierMasterIndex';

IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @SuperAdminGroupId AND RoleId = @StateMasterIndex)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId) VALUES (@SuperAdminGroupId, @StateMasterIndex);
    PRINT '✓ Added: StateMasterIndex';
END
ELSE
    PRINT '○ Already exists: StateMasterIndex';

IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @SuperAdminGroupId AND RoleId = @UnitMasterIndex)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId) VALUES (@SuperAdminGroupId, @UnitMasterIndex);
    PRINT '✓ Added: UnitMasterIndex';
END
ELSE
    PRINT '○ Already exists: UnitMasterIndex';

-- =============================================
-- FIX ADMIN (GroupId = 2)
-- =============================================
DECLARE @AdminGroupId INT = 2;

PRINT '';
PRINT '========================================';
PRINT 'FIXING ADMIN (GroupId = 2)';
PRINT '========================================';
PRINT '';
PRINT 'Step 1: REMOVING WRONG ROLES...';
PRINT '----------------------------------------';

-- Remove wrong roles from Admin
IF EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @AdminGroupId AND RoleId = @SupplierMasterEdit)
BEGIN
    DELETE FROM ApplicationRoleGroups WHERE GroupId = @AdminGroupId AND RoleId = @SupplierMasterEdit;
    PRINT '✓ Removed: SupplierMasterEdit';
END
ELSE
    PRINT '○ Not found: SupplierMasterEdit';

IF EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @AdminGroupId AND RoleId = @PurchaseInvoiceApprovalPrint)
BEGIN
    DELETE FROM ApplicationRoleGroups WHERE GroupId = @AdminGroupId AND RoleId = @PurchaseInvoiceApprovalPrint;
    PRINT '✓ Removed: PurchaseInvoiceApprovalPrint';
END
ELSE
    PRINT '○ Not found: PurchaseInvoiceApprovalPrint';

IF EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @AdminGroupId AND RoleId = @StockViewPrint)
BEGIN
    DELETE FROM ApplicationRoleGroups WHERE GroupId = @AdminGroupId AND RoleId = @StockViewPrint;
    PRINT '✓ Removed: StockViewPrint';
END
ELSE
    PRINT '○ Not found: StockViewPrint';

PRINT '';
PRINT 'Step 2: ADDING CORRECT INDEX ROLES...';
PRINT '----------------------------------------';

-- Add correct roles to Admin
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @AdminGroupId AND RoleId = @SupplierMasterIndex)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId) VALUES (@AdminGroupId, @SupplierMasterIndex);
    PRINT '✓ Added: SupplierMasterIndex';
END
ELSE
    PRINT '○ Already exists: SupplierMasterIndex';

IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @AdminGroupId AND RoleId = @StateMasterIndex)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId) VALUES (@AdminGroupId, @StateMasterIndex);
    PRINT '✓ Added: StateMasterIndex';
END
ELSE
    PRINT '○ Already exists: StateMasterIndex';

IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @AdminGroupId AND RoleId = @UnitMasterIndex)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId) VALUES (@AdminGroupId, @UnitMasterIndex);
    PRINT '✓ Added: UnitMasterIndex';
END
ELSE
    PRINT '○ Already exists: UnitMasterIndex';

-- =============================================
-- VERIFICATION
-- =============================================
PRINT '';
PRINT '========================================';
PRINT 'VERIFICATION - BOTH GROUPS';
PRINT '========================================';

SELECT 
    arg.GroupId,
    g.Name AS GroupName,
    r.Name AS RoleName,
    r.Description
FROM ApplicationRoleGroups arg
INNER JOIN Groups g ON arg.GroupId = g.Id
INNER JOIN AspNetRoles r ON arg.RoleId = r.Id
WHERE arg.GroupId IN (1, 2)
  AND r.Name IN ('SupplierMasterIndex', 'StateMasterIndex', 'UnitMasterIndex')
ORDER BY arg.GroupId, r.Name;

PRINT '';
PRINT '========================================';
PRINT '✅ Done! Fixed both SuperAdmin and Admin.';
PRINT '⚠️  Now LOGOUT and LOGIN to refresh roles.';
PRINT '';
PRINT 'Expected: All 3 menus should appear for both groups:';
PRINT '  ✓ Supplier Master';
PRINT '  ✓ State Master';
PRINT '  ✓ Unit Master';
PRINT '========================================';
