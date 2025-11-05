-- =============================================
-- Script: Add Invoice Approval Roles
-- Description: Adds PurchaseInvoiceApproval roles to AspNetRoles and assigns to Admin groups
-- Date: 2025-11-06
-- =============================================

USE [KVM_ERP_DB]
GO

PRINT '=========================================='
PRINT 'Adding Invoice Approval Roles'
PRINT '=========================================='
PRINT ''

-- =============================================
-- STEP 1: Add Roles to AspNetRoles Table
-- =============================================

PRINT 'Step 1: Adding roles to AspNetRoles...'

-- Check if PurchaseInvoiceApprovalIndex role exists
IF NOT EXISTS (SELECT 1 FROM AspNetRoles WHERE Name = 'PurchaseInvoiceApprovalIndex')
BEGIN
    INSERT INTO AspNetRoles (Id, Name)
    VALUES (NEWID(), 'PurchaseInvoiceApprovalIndex')
    PRINT '  ✓ Added role: PurchaseInvoiceApprovalIndex'
END
ELSE
BEGIN
    PRINT '  ⚠ Role already exists: PurchaseInvoiceApprovalIndex'
END

-- Check if PurchaseInvoiceApprovalEdit role exists
IF NOT EXISTS (SELECT 1 FROM AspNetRoles WHERE Name = 'PurchaseInvoiceApprovalEdit')
BEGIN
    INSERT INTO AspNetRoles (Id, Name)
    VALUES (NEWID(), 'PurchaseInvoiceApprovalEdit')
    PRINT '  ✓ Added role: PurchaseInvoiceApprovalEdit'
END
ELSE
BEGIN
    PRINT '  ⚠ Role already exists: PurchaseInvoiceApprovalEdit'
END

-- Check if PurchaseInvoiceApprovalPrint role exists
IF NOT EXISTS (SELECT 1 FROM AspNetRoles WHERE Name = 'PurchaseInvoiceApprovalPrint')
BEGIN
    INSERT INTO AspNetRoles (Id, Name)
    VALUES (NEWID(), 'PurchaseInvoiceApprovalPrint')
    PRINT '  ✓ Added role: PurchaseInvoiceApprovalPrint'
END
ELSE
BEGIN
    PRINT '  ⚠ Role already exists: PurchaseInvoiceApprovalPrint'
END

PRINT ''

-- =============================================
-- STEP 2: Assign Roles to SuperAdmin (GroupId = 1)
-- =============================================

PRINT 'Step 2: Assigning roles to SuperAdmin (GroupId = 1)...'

DECLARE @SuperAdminGroupId INT = 1
DECLARE @IndexRoleId NVARCHAR(128)
DECLARE @EditRoleId NVARCHAR(128)
DECLARE @PrintRoleId NVARCHAR(128)

-- Get Role IDs
SELECT @IndexRoleId = Id FROM AspNetRoles WHERE Name = 'PurchaseInvoiceApprovalIndex'
SELECT @EditRoleId = Id FROM AspNetRoles WHERE Name = 'PurchaseInvoiceApprovalEdit'
SELECT @PrintRoleId = Id FROM AspNetRoles WHERE Name = 'PurchaseInvoiceApprovalPrint'

-- Assign Index role
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @SuperAdminGroupId AND RoleId = @IndexRoleId)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@SuperAdminGroupId, @IndexRoleId)
    PRINT '  ✓ Assigned PurchaseInvoiceApprovalIndex to SuperAdmin'
END
ELSE
BEGIN
    PRINT '  ⚠ SuperAdmin already has PurchaseInvoiceApprovalIndex'
END

-- Assign Edit role
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @SuperAdminGroupId AND RoleId = @EditRoleId)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@SuperAdminGroupId, @EditRoleId)
    PRINT '  ✓ Assigned PurchaseInvoiceApprovalEdit to SuperAdmin'
END
ELSE
BEGIN
    PRINT '  ⚠ SuperAdmin already has PurchaseInvoiceApprovalEdit'
END

-- Assign Print role
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @SuperAdminGroupId AND RoleId = @PrintRoleId)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@SuperAdminGroupId, @PrintRoleId)
    PRINT '  ✓ Assigned PurchaseInvoiceApprovalPrint to SuperAdmin'
END
ELSE
BEGIN
    PRINT '  ⚠ SuperAdmin already has PurchaseInvoiceApprovalPrint'
END

PRINT ''

-- =============================================
-- STEP 3: Assign Roles to Admin (GroupId = 2)
-- =============================================

PRINT 'Step 3: Assigning roles to Admin (GroupId = 2)...'

DECLARE @AdminGroupId INT = 2

-- Assign Index role
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @AdminGroupId AND RoleId = @IndexRoleId)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@AdminGroupId, @IndexRoleId)
    PRINT '  ✓ Assigned PurchaseInvoiceApprovalIndex to Admin'
END
ELSE
BEGIN
    PRINT '  ⚠ Admin already has PurchaseInvoiceApprovalIndex'
END

-- Assign Edit role
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @AdminGroupId AND RoleId = @EditRoleId)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@AdminGroupId, @EditRoleId)
    PRINT '  ✓ Assigned PurchaseInvoiceApprovalEdit to Admin'
END
ELSE
BEGIN
    PRINT '  ⚠ Admin already has PurchaseInvoiceApprovalEdit'
END

-- Assign Print role
IF NOT EXISTS (SELECT 1 FROM ApplicationRoleGroups WHERE GroupId = @AdminGroupId AND RoleId = @PrintRoleId)
BEGIN
    INSERT INTO ApplicationRoleGroups (GroupId, RoleId)
    VALUES (@AdminGroupId, @PrintRoleId)
    PRINT '  ✓ Assigned PurchaseInvoiceApprovalPrint to Admin'
END
ELSE
BEGIN
    PRINT '  ⚠ Admin already has PurchaseInvoiceApprovalPrint'
END

PRINT ''

-- =============================================
-- STEP 4: Verify the assignments
-- =============================================

PRINT 'Step 4: Verifying role assignments...'
PRINT ''

SELECT 
    g.GroupId,
    g.GroupName,
    r.Name as RoleName
FROM ApplicationRoleGroups arg
INNER JOIN ApplicationGroups g ON arg.GroupId = g.GroupId
INNER JOIN AspNetRoles r ON arg.RoleId = r.Id
WHERE r.Name LIKE 'PurchaseInvoiceApproval%'
ORDER BY g.GroupId, r.Name

PRINT ''
PRINT '=========================================='
PRINT 'Invoice Approval Roles Added Successfully!'
PRINT '=========================================='
PRINT ''
PRINT 'Roles Added:'
PRINT '  - PurchaseInvoiceApprovalIndex'
PRINT '  - PurchaseInvoiceApprovalEdit'
PRINT '  - PurchaseInvoiceApprovalPrint'
PRINT ''
PRINT 'Assigned to Groups:'
PRINT '  - SuperAdmin (GroupId = 1)'
PRINT '  - Admin (GroupId = 2)'
PRINT ''
PRINT 'Next Steps:'
PRINT '  1. Rebuild the solution'
PRINT '  2. Run the application'
PRINT '  3. Navigate to: /PurchaseInvoiceApproval/Index'
PRINT '  4. Verify only "Waiting for Approval" invoices are shown'
PRINT ''
