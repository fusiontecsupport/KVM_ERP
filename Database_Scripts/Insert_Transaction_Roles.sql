-- =============================================
-- Insert Roles for Transaction Menu in KVM_ERP
-- RMenuGroupId = 1 (Transaction Menu)
-- Each Transaction has 4 actions: Index, Create, Edit, Delete
-- Total: 12 Records (3 Transactions × 4 Actions)
-- =============================================

-- Clear existing Transaction roles if needed (OPTIONAL - COMMENT OUT IF NOT NEEDED)
-- DELETE FROM AspNetRoles WHERE RMenuGroupId = 1;

-- =============================================
-- 1. RAW MATERIAL INTAKE (Order: 1)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'RawMaterialIntakeIndex', 'Can View Raw Material Intake', 'ApplicationRole', 'Raw Material Intake', 'RawMaterialIntake', 1, 1, 'Index', 1, 'fa fa-truck-loading'),
(NEWID(), 'RawMaterialIntakeCreate', 'Can Create Raw Material Intake', 'ApplicationRole', 'Raw Material Intake', 'RawMaterialIntake', 1, 1, 'Create', 1, 'fa fa-truck-loading'),
(NEWID(), 'RawMaterialIntakeEdit', 'Can Edit Raw Material Intake', 'ApplicationRole', 'Raw Material Intake', 'RawMaterialIntake', 1, 1, 'Edit', 1, 'fa fa-truck-loading'),
(NEWID(), 'RawMaterialIntakeDelete', 'Can Delete Raw Material Intake', 'ApplicationRole', 'Raw Material Intake', 'RawMaterialIntake', 1, 1, 'Delete', 1, 'fa fa-truck-loading');

-- =============================================
-- 2. STOCK VIEW (Order: 2)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'StockViewIndex', 'Can View Stock View', 'ApplicationRole', 'Stock View', 'StockView', 1, 2, 'Index', 1, 'fa fa-chart-line'),
(NEWID(), 'StockViewCreate', 'Can Create Stock View', 'ApplicationRole', 'Stock View', 'StockView', 1, 2, 'Create', 1, 'fa fa-chart-line'),
(NEWID(), 'StockViewEdit', 'Can Edit Stock View', 'ApplicationRole', 'Stock View', 'StockView', 1, 2, 'Edit', 1, 'fa fa-chart-line'),
(NEWID(), 'StockViewDelete', 'Can Delete Stock View', 'ApplicationRole', 'Stock View', 'StockView', 1, 2, 'Delete', 1, 'fa fa-chart-line');

-- =============================================
-- 3. INVOICE (Order: 3)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'RawMaterialInvoiceIndex', 'Can View Invoice', 'ApplicationRole', 'Invoice', 'RawMaterialInvoice', 1, 3, 'Index', 1, 'fa fa-file-invoice'),
(NEWID(), 'RawMaterialInvoiceCreate', 'Can Create Invoice', 'ApplicationRole', 'Invoice', 'RawMaterialInvoice', 1, 3, 'Create', 1, 'fa fa-file-invoice'),
(NEWID(), 'RawMaterialInvoiceEdit', 'Can Edit Invoice', 'ApplicationRole', 'Invoice', 'RawMaterialInvoice', 1, 3, 'Edit', 1, 'fa fa-file-invoice'),
(NEWID(), 'RawMaterialInvoiceDelete', 'Can Delete Invoice', 'ApplicationRole', 'Invoice', 'RawMaterialInvoice', 1, 3, 'Delete', 1, 'fa fa-file-invoice');

-- =============================================
-- VERIFICATION QUERY
-- Run this to verify all 12 roles were inserted
-- =============================================
SELECT 
    RMenuGroupId,
    RMenuGroupOrder,
    RMenuType,
    RControllerName,
    RMenuIndex,
    Name,
    Description,
    RImageClassName
FROM AspNetRoles
WHERE RMenuGroupId = 1
ORDER BY RMenuGroupOrder, 
    CASE RMenuIndex 
        WHEN 'Index' THEN 1 
        WHEN 'Create' THEN 2 
        WHEN 'Edit' THEN 3 
        WHEN 'Delete' THEN 4 
    END;

-- Expected Result: 12 rows (3 transactions × 4 actions each)

-- =============================================
-- COMPLETE TRANSACTION STRUCTURE SUMMARY
-- =============================================
/*
Transaction Menu (RMenuGroupId = 1):
┌─────┬──────────────────────────┬─────────────────────────┬───────┬───────────────────────┐
│ Ord │ Transaction Name         │ Controller              │ Order │ Icon                  │
├─────┼──────────────────────────┼─────────────────────────┼───────┼───────────────────────┤
│  1  │ Raw Material Intake      │ RawMaterialIntake       │   1   │ fa fa-truck-loading   │
│  2  │ Stock View               │ StockView               │   2   │ fa fa-chart-line      │
│  3  │ Invoice                  │ RawMaterialInvoice      │   3   │ fa fa-file-invoice    │
└─────┴──────────────────────────┴─────────────────────────┴───────┴───────────────────────┘

Each Transaction has 4 permissions:
- Index  (View)
- Create (Add New)
- Edit   (Modify)
- Delete (Remove)

Total: 12 role records for Transaction menu
*/
