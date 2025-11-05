-- =============================================
-- TRANSACTION MENU ROLES - INSERT SCRIPT
-- =============================================
-- Description: Creates roles for Transaction menu items with proper permissions
-- RMenuGroupId: 1 (Transaction Menu)
-- Date: 2025-11-05
-- =============================================

-- USE [KVM_ERP_DB]  -- Comment this out if your database has a different name
-- GO
-- Make sure you're connected to the correct database in SSMS before running this script

-- =============================================
-- 1. RAW MATERIALS INTAKE (Order: 1)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'RawMaterialIntakeIndex', 'Can View Raw Materials Intake', 'ApplicationRole', 'Raw Materials Intake', 'RawMaterialIntake', 1, 1, 'Index', 1, 'fa fa-truck-loading'),
(NEWID(), 'RawMaterialIntakeCreate', 'Can Create Raw Materials Intake', 'ApplicationRole', 'Raw Materials Intake', 'RawMaterialIntake', 1, 1, 'Create', 1, 'fa fa-truck-loading'),
(NEWID(), 'RawMaterialIntakeEdit', 'Can Edit Raw Materials Intake', 'ApplicationRole', 'Raw Materials Intake', 'RawMaterialIntake', 1, 1, 'Edit', 1, 'fa fa-truck-loading'),
(NEWID(), 'RawMaterialIntakeDelete', 'Can Delete Raw Materials Intake', 'ApplicationRole', 'Raw Materials Intake', 'RawMaterialIntake', 1, 1, 'Delete', 1, 'fa fa-truck-loading'),
(NEWID(), 'RawMaterialIntakePrint', 'Can Print Raw Materials Intake', 'ApplicationRole', 'Raw Materials Intake', 'RawMaterialIntake', 1, 1, 'Print', 1, 'fa fa-truck-loading'),
(NEWID(), 'RawMaterialIntakeCalculationPrint', 'Can Print Calculation for Raw Materials Intake', 'ApplicationRole', 'Raw Materials Intake', 'RawMaterialIntake', 1, 1, 'CalculationPrint', 1, 'fa fa-truck-loading');

-- =============================================
-- 2. STOCK VIEW (Order: 2)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'StockViewIndex', 'Can View Stock', 'ApplicationRole', 'Stock View', 'StockView', 1, 2, 'Index', 1, 'fa fa-boxes'),
(NEWID(), 'StockViewPrint', 'Can Print Stock View', 'ApplicationRole', 'Stock View', 'StockView', 1, 2, 'Print', 1, 'fa fa-boxes');

-- =============================================
-- 3. INVOICE (PURCHASE INVOICE) (Order: 3)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'PurchaseInvoiceIndex', 'Can View Purchase Invoice', 'ApplicationRole', 'Invoice', 'PurchaseInvoice', 1, 3, 'Index', 1, 'fa fa-file-invoice'),
(NEWID(), 'PurchaseInvoiceCreate', 'Can Create Purchase Invoice', 'ApplicationRole', 'Invoice', 'PurchaseInvoice', 1, 3, 'Create', 1, 'fa fa-file-invoice'),
(NEWID(), 'PurchaseInvoiceEdit', 'Can Edit Purchase Invoice', 'ApplicationRole', 'Invoice', 'PurchaseInvoice', 1, 3, 'Edit', 1, 'fa fa-file-invoice'),
(NEWID(), 'PurchaseInvoiceDelete', 'Can Delete Purchase Invoice', 'ApplicationRole', 'Invoice', 'PurchaseInvoice', 1, 3, 'Delete', 1, 'fa fa-file-invoice'),
(NEWID(), 'PurchaseInvoicePrint', 'Can Print Purchase Invoice', 'ApplicationRole', 'Invoice', 'PurchaseInvoice', 1, 3, 'Print', 1, 'fa fa-file-invoice');

-- =============================================
-- 4. PURCHASE INVOICE APPROVAL (NEW - Order: 4)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'PurchaseInvoiceApprovalIndex', 'Can View Purchase Invoice Approval', 'ApplicationRole', 'Purchase Invoice Approval', 'PurchaseInvoiceApproval', 1, 4, 'Index', 1, 'fa fa-check-circle'),
(NEWID(), 'PurchaseInvoiceApprovalEdit', 'Can Edit Purchase Invoice Approval', 'ApplicationRole', 'Purchase Invoice Approval', 'PurchaseInvoiceApproval', 1, 4, 'Edit', 1, 'fa fa-check-circle'),
(NEWID(), 'PurchaseInvoiceApprovalPrint', 'Can Print Purchase Invoice Approval', 'ApplicationRole', 'Purchase Invoice Approval', 'PurchaseInvoiceApproval', 1, 4, 'Print', 1, 'fa fa-check-circle');

GO

-- =============================================
-- SUMMARY
-- =============================================
-- Total Transaction Menu Roles Created: 16
-- 
-- Breakdown by Menu Item:
-- 1. Raw Materials Intake: 6 roles (Index, Create, Edit, Delete, Print, CalculationPrint)
-- 2. Stock View: 2 roles (Index, Print)
-- 3. Purchase Invoice: 5 roles (Index, Create, Edit, Delete, Print)
-- 4. Purchase Invoice Approval: 3 roles (Index, Edit, Print)
-- 
-- RMenuGroupId: 1 (Transaction Menu)
-- =============================================

-- Verify inserted roles
SELECT 
    Name AS RoleName,
    Description,
    RMenuType AS MenuName,
    RControllerName AS Controller,
    RMenuGroupId AS GroupId,
    RMenuGroupOrder AS [Order],
    RMenuIndex AS Action,
    RImageClassName AS Icon
FROM AspNetRoles
WHERE RMenuGroupId = 1
ORDER BY RMenuGroupOrder, Name;
