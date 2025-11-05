-- =============================================
-- COMPLETE ROLE-BASED ACCESS CONTROL SETUP
-- Insert ALL Roles for KVM_ERP System
-- =============================================
-- This script includes:
-- 1. Transaction Menu (RMenuGroupId = 1) - 3 items × 4 actions = 12 roles
-- 2. Tally Menu (RMenuGroupId = 2) - 1 item × 4 actions = 4 roles
-- 3. Reports Menu (RMenuGroupId = 3) - 1 item × 4 actions = 4 roles
-- 4. Masters Menu (RMenuGroupId = 4) - 16 items × 4 actions = 64 roles
-- =============================================
-- TOTAL: 84 Role Records
-- =============================================

-- OPTIONAL: Clear existing menu roles if needed (UNCOMMENT IF NEEDED)
/*
DELETE FROM AspNetRoles WHERE RMenuGroupId IN (1, 2, 3, 4);
*/

-- =============================================
-- TRANSACTION MENU (RMenuGroupId = 1)
-- =============================================

-- 1. Raw Material Intake
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'RawMaterialIntakeIndex', 'Can View Raw Material Intake', 'ApplicationRole', 'Raw Material Intake', 'RawMaterialIntake', 1, 1, 'Index', 1, 'fa fa-truck-loading'),
(NEWID(), 'RawMaterialIntakeCreate', 'Can Create Raw Material Intake', 'ApplicationRole', 'Raw Material Intake', 'RawMaterialIntake', 1, 1, 'Create', 1, 'fa fa-truck-loading'),
(NEWID(), 'RawMaterialIntakeEdit', 'Can Edit Raw Material Intake', 'ApplicationRole', 'Raw Material Intake', 'RawMaterialIntake', 1, 1, 'Edit', 1, 'fa fa-truck-loading'),
(NEWID(), 'RawMaterialIntakeDelete', 'Can Delete Raw Material Intake', 'ApplicationRole', 'Raw Material Intake', 'RawMaterialIntake', 1, 1, 'Delete', 1, 'fa fa-truck-loading');

-- 2. Stock View
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'StockViewIndex', 'Can View Stock View', 'ApplicationRole', 'Stock View', 'StockView', 1, 2, 'Index', 1, 'fa fa-chart-line'),
(NEWID(), 'StockViewCreate', 'Can Create Stock View', 'ApplicationRole', 'Stock View', 'StockView', 1, 2, 'Create', 1, 'fa fa-chart-line'),
(NEWID(), 'StockViewEdit', 'Can Edit Stock View', 'ApplicationRole', 'Stock View', 'StockView', 1, 2, 'Edit', 1, 'fa fa-chart-line'),
(NEWID(), 'StockViewDelete', 'Can Delete Stock View', 'ApplicationRole', 'Stock View', 'StockView', 1, 2, 'Delete', 1, 'fa fa-chart-line');

-- 3. Invoice
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'RawMaterialInvoiceIndex', 'Can View Invoice', 'ApplicationRole', 'Invoice', 'RawMaterialInvoice', 1, 3, 'Index', 1, 'fa fa-file-invoice'),
(NEWID(), 'RawMaterialInvoiceCreate', 'Can Create Invoice', 'ApplicationRole', 'Invoice', 'RawMaterialInvoice', 1, 3, 'Create', 1, 'fa fa-file-invoice'),
(NEWID(), 'RawMaterialInvoiceEdit', 'Can Edit Invoice', 'ApplicationRole', 'Invoice', 'RawMaterialInvoice', 1, 3, 'Edit', 1, 'fa fa-file-invoice'),
(NEWID(), 'RawMaterialInvoiceDelete', 'Can Delete Invoice', 'ApplicationRole', 'Invoice', 'RawMaterialInvoice', 1, 3, 'Delete', 1, 'fa fa-file-invoice');

-- =============================================
-- TALLY MENU (RMenuGroupId = 2)
-- =============================================

-- 1. Invoice Updation to Tally
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'TallyInvoiceUpdationIndex', 'Can View Invoice Updation to Tally', 'ApplicationRole', 'Invoice Updation to Tally', 'TallyInvoiceUpdation', 2, 1, 'Index', 1, 'fa fa-sync-alt'),
(NEWID(), 'TallyInvoiceUpdationCreate', 'Can Create Invoice Updation to Tally', 'ApplicationRole', 'Invoice Updation to Tally', 'TallyInvoiceUpdation', 2, 1, 'Create', 1, 'fa fa-sync-alt'),
(NEWID(), 'TallyInvoiceUpdationEdit', 'Can Edit Invoice Updation to Tally', 'ApplicationRole', 'Invoice Updation to Tally', 'TallyInvoiceUpdation', 2, 1, 'Edit', 1, 'fa fa-sync-alt'),
(NEWID(), 'TallyInvoiceUpdationDelete', 'Can Delete Invoice Updation to Tally', 'ApplicationRole', 'Invoice Updation to Tally', 'TallyInvoiceUpdation', 2, 1, 'Delete', 1, 'fa fa-sync-alt');

-- =============================================
-- REPORTS MENU (RMenuGroupId = 3)
-- =============================================

-- 1. Raw Materials Import Report
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'RawMaterialsImportReportIndex', 'Can View Raw Materials Import Report', 'ApplicationRole', 'Raw Materials Import Report', 'Reports', 3, 1, 'Index', 1, 'fa fa-file-excel'),
(NEWID(), 'RawMaterialsImportReportCreate', 'Can Create Raw Materials Import Report', 'ApplicationRole', 'Raw Materials Import Report', 'Reports', 3, 1, 'Create', 1, 'fa fa-file-excel'),
(NEWID(), 'RawMaterialsImportReportEdit', 'Can Edit Raw Materials Import Report', 'ApplicationRole', 'Raw Materials Import Report', 'Reports', 3, 1, 'Edit', 1, 'fa fa-file-excel'),
(NEWID(), 'RawMaterialsImportReportDelete', 'Can Delete Raw Materials Import Report', 'ApplicationRole', 'Raw Materials Import Report', 'Reports', 3, 1, 'Delete', 1, 'fa fa-file-excel');

-- =============================================
-- MASTERS MENU (RMenuGroupId = 4)
-- =============================================

-- 1. Company Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'CompanyMasterIndex', 'Can View Company Master', 'ApplicationRole', 'Company Master', 'CompanyMaster', 4, 1, 'Index', 1, 'fa fa-building'),
(NEWID(), 'CompanyMasterCreate', 'Can Create Company Master', 'ApplicationRole', 'Company Master', 'CompanyMaster', 4, 1, 'Create', 1, 'fa fa-building'),
(NEWID(), 'CompanyMasterEdit', 'Can Edit Company Master', 'ApplicationRole', 'Company Master', 'CompanyMaster', 4, 1, 'Edit', 1, 'fa fa-building'),
(NEWID(), 'CompanyMasterDelete', 'Can Delete Company Master', 'ApplicationRole', 'Company Master', 'CompanyMaster', 4, 1, 'Delete', 1, 'fa fa-building');

-- 2. Designation Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'DesginationMasterIndex', 'Can View Designation Master', 'ApplicationRole', 'Designation Master', 'DesginationMaster', 4, 2, 'Index', 1, 'fa fa-id-badge'),
(NEWID(), 'DesginationMasterCreate', 'Can Create Designation Master', 'ApplicationRole', 'Designation Master', 'DesginationMaster', 4, 2, 'Create', 1, 'fa fa-id-badge'),
(NEWID(), 'DesginationMasterEdit', 'Can Edit Designation Master', 'ApplicationRole', 'Designation Master', 'DesginationMaster', 4, 2, 'Edit', 1, 'fa fa-id-badge'),
(NEWID(), 'DesginationMasterDelete', 'Can Delete Designation Master', 'ApplicationRole', 'Designation Master', 'DesginationMaster', 4, 2, 'Delete', 1, 'fa fa-id-badge');

-- 3. Department Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'DepartmentMasterIndex', 'Can View Department Master', 'ApplicationRole', 'Department Master', 'DepartmentMaster', 4, 3, 'Index', 1, 'fa fa-sitemap'),
(NEWID(), 'DepartmentMasterCreate', 'Can Create Department Master', 'ApplicationRole', 'Department Master', 'DepartmentMaster', 4, 3, 'Create', 1, 'fa fa-sitemap'),
(NEWID(), 'DepartmentMasterEdit', 'Can Edit Department Master', 'ApplicationRole', 'Department Master', 'DepartmentMaster', 4, 3, 'Edit', 1, 'fa fa-sitemap'),
(NEWID(), 'DepartmentMasterDelete', 'Can Delete Department Master', 'ApplicationRole', 'Department Master', 'DepartmentMaster', 4, 3, 'Delete', 1, 'fa fa-sitemap');

-- 4. Cost Factor Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'CostFactorMasterIndex', 'Can View Cost Factor Master', 'ApplicationRole', 'Cost Factor Master', 'CostFactorMaster', 4, 4, 'Index', 1, 'fa fa-calculator'),
(NEWID(), 'CostFactorMasterCreate', 'Can Create Cost Factor Master', 'ApplicationRole', 'Cost Factor Master', 'CostFactorMaster', 4, 4, 'Create', 1, 'fa fa-calculator'),
(NEWID(), 'CostFactorMasterEdit', 'Can Edit Cost Factor Master', 'ApplicationRole', 'Cost Factor Master', 'CostFactorMaster', 4, 4, 'Edit', 1, 'fa fa-calculator'),
(NEWID(), 'CostFactorMasterDelete', 'Can Delete Cost Factor Master', 'ApplicationRole', 'Cost Factor Master', 'CostFactorMaster', 4, 4, 'Delete', 1, 'fa fa-calculator');

-- 5. HSN Code Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'HSNCodeMasterIndex', 'Can View HSN Code Master', 'ApplicationRole', 'HSN Code Master', 'HSNCodeMaster', 4, 5, 'Index', 1, 'fa fa-barcode'),
(NEWID(), 'HSNCodeMasterCreate', 'Can Create HSN Code Master', 'ApplicationRole', 'HSN Code Master', 'HSNCodeMaster', 4, 5, 'Create', 1, 'fa fa-barcode'),
(NEWID(), 'HSNCodeMasterEdit', 'Can Edit HSN Code Master', 'ApplicationRole', 'HSN Code Master', 'HSNCodeMaster', 4, 5, 'Edit', 1, 'fa fa-barcode'),
(NEWID(), 'HSNCodeMasterDelete', 'Can Delete HSN Code Master', 'ApplicationRole', 'HSN Code Master', 'HSNCodeMaster', 4, 5, 'Delete', 1, 'fa fa-barcode');

-- 6. Customer Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'CustomerMasterIndex', 'Can View Customer Master', 'ApplicationRole', 'Customer Master', 'CustomerMaster', 4, 6, 'Index', 1, 'fa-solid fa-person'),
(NEWID(), 'CustomerMasterCreate', 'Can Create Customer Master', 'ApplicationRole', 'Customer Master', 'CustomerMaster', 4, 6, 'Create', 1, 'fa-solid fa-person'),
(NEWID(), 'CustomerMasterEdit', 'Can Edit Customer Master', 'ApplicationRole', 'Customer Master', 'CustomerMaster', 4, 6, 'Edit', 1, 'fa-solid fa-person'),
(NEWID(), 'CustomerMasterDelete', 'Can Delete Customer Master', 'ApplicationRole', 'Customer Master', 'CustomerMaster', 4, 6, 'Delete', 1, 'fa-solid fa-person');

-- 7. Supplier Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'SupplierMasterIndex', 'Can View Supplier Master', 'ApplicationRole', 'Supplier Master', 'SupplierMaster', 4, 7, 'Index', 1, 'fa fa-truck'),
(NEWID(), 'SupplierMasterCreate', 'Can Create Supplier Master', 'ApplicationRole', 'Supplier Master', 'SupplierMaster', 4, 7, 'Create', 1, 'fa fa-truck'),
(NEWID(), 'SupplierMasterEdit', 'Can Edit Supplier Master', 'ApplicationRole', 'Supplier Master', 'SupplierMaster', 4, 7, 'Edit', 1, 'fa fa-truck'),
(NEWID(), 'SupplierMasterDelete', 'Can Delete Supplier Master', 'ApplicationRole', 'Supplier Master', 'SupplierMaster', 4, 7, 'Delete', 1, 'fa fa-truck');

-- 8. Location Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'LocationMasterIndex', 'Can View Location Master', 'ApplicationRole', 'Location Master', 'LocationMaster', 4, 8, 'Index', 1, 'fa-solid fa-map-location-dot'),
(NEWID(), 'LocationMasterCreate', 'Can Create Location Master', 'ApplicationRole', 'Location Master', 'LocationMaster', 4, 8, 'Create', 1, 'fa-solid fa-map-location-dot'),
(NEWID(), 'LocationMasterEdit', 'Can Edit Location Master', 'ApplicationRole', 'Location Master', 'LocationMaster', 4, 8, 'Edit', 1, 'fa-solid fa-map-location-dot'),
(NEWID(), 'LocationMasterDelete', 'Can Delete Location Master', 'ApplicationRole', 'Location Master', 'LocationMaster', 4, 8, 'Delete', 1, 'fa-solid fa-map-location-dot');

-- 9. State Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'StateMasterIndex', 'Can View State Master', 'ApplicationRole', 'State Master', 'StateMaster', 4, 9, 'Index', 1, 'fa-solid fa-compass'),
(NEWID(), 'StateMasterCreate', 'Can Create State Master', 'ApplicationRole', 'State Master', 'StateMaster', 4, 9, 'Create', 1, 'fa-solid fa-compass'),
(NEWID(), 'StateMasterEdit', 'Can Edit State Master', 'ApplicationRole', 'State Master', 'StateMaster', 4, 9, 'Edit', 1, 'fa-solid fa-compass'),
(NEWID(), 'StateMasterDelete', 'Can Delete State Master', 'ApplicationRole', 'State Master', 'StateMaster', 4, 9, 'Delete', 1, 'fa-solid fa-compass');

-- 10. Unit Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'UnitMasterIndex', 'Can View Unit Master', 'ApplicationRole', 'Unit Master', 'UnitMaster', 4, 10, 'Index', 1, 'fa fa-balance-scale'),
(NEWID(), 'UnitMasterCreate', 'Can Create Unit Master', 'ApplicationRole', 'Unit Master', 'UnitMaster', 4, 10, 'Create', 1, 'fa fa-balance-scale'),
(NEWID(), 'UnitMasterEdit', 'Can Edit Unit Master', 'ApplicationRole', 'Unit Master', 'UnitMaster', 4, 10, 'Edit', 1, 'fa fa-balance-scale'),
(NEWID(), 'UnitMasterDelete', 'Can Delete Unit Master', 'ApplicationRole', 'Unit Master', 'UnitMaster', 4, 10, 'Delete', 1, 'fa fa-balance-scale');

-- 11. Material Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'MaterialMasterIndex', 'Can View Material Master', 'ApplicationRole', 'Material Master', 'MaterialMaster', 4, 11, 'Index', 1, 'fa-solid fa-atom'),
(NEWID(), 'MaterialMasterCreate', 'Can Create Material Master', 'ApplicationRole', 'Material Master', 'MaterialMaster', 4, 11, 'Create', 1, 'fa-solid fa-atom'),
(NEWID(), 'MaterialMasterEdit', 'Can Edit Material Master', 'ApplicationRole', 'Material Master', 'MaterialMaster', 4, 11, 'Edit', 1, 'fa-solid fa-atom'),
(NEWID(), 'MaterialMasterDelete', 'Can Delete Material Master', 'ApplicationRole', 'Material Master', 'MaterialMaster', 4, 11, 'Delete', 1, 'fa-solid fa-atom');

-- 12. Material Type Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'MaterialTypeMasterIndex', 'Can View Material Type Master', 'ApplicationRole', 'Material Type Master', 'MaterialTypeMaster', 4, 12, 'Index', 1, 'fa fa-cubes'),
(NEWID(), 'MaterialTypeMasterCreate', 'Can Create Material Type Master', 'ApplicationRole', 'Material Type Master', 'MaterialTypeMaster', 4, 12, 'Create', 1, 'fa fa-cubes'),
(NEWID(), 'MaterialTypeMasterEdit', 'Can Edit Material Type Master', 'ApplicationRole', 'Material Type Master', 'MaterialTypeMaster', 4, 12, 'Edit', 1, 'fa fa-cubes'),
(NEWID(), 'MaterialTypeMasterDelete', 'Can Delete Material Type Master', 'ApplicationRole', 'Material Type Master', 'MaterialTypeMaster', 4, 12, 'Delete', 1, 'fa fa-cubes');

-- 13. Material Group Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'MaterialGroupMasterIndex', 'Can View Material Group Master', 'ApplicationRole', 'Material Group Master', 'MaterialGroupMaster', 4, 13, 'Index', 1, 'fa fa-layer-group'),
(NEWID(), 'MaterialGroupMasterCreate', 'Can Create Material Group Master', 'ApplicationRole', 'Material Group Master', 'MaterialGroupMaster', 4, 13, 'Create', 1, 'fa fa-layer-group'),
(NEWID(), 'MaterialGroupMasterEdit', 'Can Edit Material Group Master', 'ApplicationRole', 'Material Group Master', 'MaterialGroupMaster', 4, 13, 'Edit', 1, 'fa fa-layer-group'),
(NEWID(), 'MaterialGroupMasterDelete', 'Can Delete Material Group Master', 'ApplicationRole', 'Material Group Master', 'MaterialGroupMaster', 4, 13, 'Delete', 1, 'fa fa-layer-group');

-- 14. Packing Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'PackingMasterIndex', 'Can View Packing Master', 'ApplicationRole', 'Packing Master', 'PackingMaster', 4, 14, 'Index', 1, 'fa fa-box'),
(NEWID(), 'PackingMasterCreate', 'Can Create Packing Master', 'ApplicationRole', 'Packing Master', 'PackingMaster', 4, 14, 'Create', 1, 'fa fa-box'),
(NEWID(), 'PackingMasterEdit', 'Can Edit Packing Master', 'ApplicationRole', 'Packing Master', 'PackingMaster', 4, 14, 'Edit', 1, 'fa fa-box'),
(NEWID(), 'PackingMasterDelete', 'Can Delete Packing Master', 'ApplicationRole', 'Packing Master', 'PackingMaster', 4, 14, 'Delete', 1, 'fa fa-box');

-- 15. Packing Type Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'PackingTypeMasterIndex', 'Can View Packing Type Master', 'ApplicationRole', 'Packing Type Master', 'PackingTypeMaster', 4, 15, 'Index', 1, 'fa fa-cube'),
(NEWID(), 'PackingTypeMasterCreate', 'Can Create Packing Type Master', 'ApplicationRole', 'Packing Type Master', 'PackingTypeMaster', 4, 15, 'Create', 1, 'fa fa-cube'),
(NEWID(), 'PackingTypeMasterEdit', 'Can Edit Packing Type Master', 'ApplicationRole', 'Packing Type Master', 'PackingTypeMaster', 4, 15, 'Edit', 1, 'fa fa-cube'),
(NEWID(), 'PackingTypeMasterDelete', 'Can Delete Packing Type Master', 'ApplicationRole', 'Packing Type Master', 'PackingTypeMaster', 4, 15, 'Delete', 1, 'fa fa-cube');

-- 16. Laboratory Master
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'LaboratoryMasterIndex', 'Can View Laboratory Master', 'ApplicationRole', 'Laboratory Master', 'LaboratoryMaster', 4, 16, 'Index', 1, 'fa fa-flask'),
(NEWID(), 'LaboratoryMasterCreate', 'Can Create Laboratory Master', 'ApplicationRole', 'Laboratory Master', 'LaboratoryMaster', 4, 16, 'Create', 1, 'fa fa-flask'),
(NEWID(), 'LaboratoryMasterEdit', 'Can Edit Laboratory Master', 'ApplicationRole', 'Laboratory Master', 'LaboratoryMaster', 4, 16, 'Edit', 1, 'fa fa-flask'),
(NEWID(), 'LaboratoryMasterDelete', 'Can Delete Laboratory Master', 'ApplicationRole', 'Laboratory Master', 'LaboratoryMaster', 4, 16, 'Delete', 1, 'fa fa-flask');

-- =============================================
-- VERIFICATION QUERIES
-- =============================================

PRINT '============================================='
PRINT 'VERIFICATION: Counting inserted roles'
PRINT '============================================='

-- Count by Menu Group
SELECT 
    RMenuGroupId,
    CASE RMenuGroupId
        WHEN 1 THEN 'Transaction'
        WHEN 2 THEN 'Tally'
        WHEN 3 THEN 'Reports'
        WHEN 4 THEN 'Masters'
    END AS MenuName,
    COUNT(*) AS TotalRoles
FROM AspNetRoles
WHERE RMenuGroupId IN (1, 2, 3, 4)
GROUP BY RMenuGroupId
ORDER BY RMenuGroupId;

PRINT ''
PRINT 'Expected Results:'
PRINT 'Transaction (1): 12 roles'
PRINT 'Tally (2):       4 roles'
PRINT 'Reports (3):     4 roles'
PRINT 'Masters (4):     64 roles'
PRINT 'TOTAL:           84 roles'
PRINT ''

-- Grand Total
SELECT 
    COUNT(*) AS GrandTotal
FROM AspNetRoles
WHERE RMenuGroupId IN (1, 2, 3, 4);

-- =============================================
-- DETAILED VIEW OF ALL ROLES
-- =============================================
/*
-- Uncomment to see all roles in detail
SELECT 
    RMenuGroupId,
    CASE RMenuGroupId
        WHEN 1 THEN 'Transaction'
        WHEN 2 THEN 'Tally'
        WHEN 3 THEN 'Reports'
        WHEN 4 THEN 'Masters'
    END AS MenuName,
    RMenuGroupOrder,
    RMenuType,
    RControllerName,
    RMenuIndex,
    Name,
    Description,
    RImageClassName
FROM AspNetRoles
WHERE RMenuGroupId IN (1, 2, 3, 4)
ORDER BY RMenuGroupId, 
    RMenuGroupOrder, 
    CASE RMenuIndex 
        WHEN 'Index' THEN 1 
        WHEN 'Create' THEN 2 
        WHEN 'Edit' THEN 3 
        WHEN 'Delete' THEN 4 
    END;
*/

PRINT '============================================='
PRINT 'SETUP COMPLETE!'
PRINT '============================================='
PRINT 'All 84 role records have been inserted.'
PRINT 'Next steps:'
PRINT '1. Go to Groups menu'
PRINT '2. Select a group'
PRINT '3. Assign permissions via the Permissions page'
PRINT '============================================='
