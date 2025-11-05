-- =============================================
-- Insert Roles for 16 Masters in KVM_ERP
-- RMenuGroupId = 4 (Masters Menu)
-- Each Master has 4 actions: Index, Create, Edit, Delete
-- Total: 64 Records
-- =============================================

-- Clear existing Masters roles if needed (OPTIONAL - COMMENT OUT IF NOT NEEDED)
-- DELETE FROM AspNetRoles WHERE RMenuGroupId = 4;

-- =============================================
-- 1. COMPANY MASTER (Order: 1)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'CompanyMasterIndex', 'Can View Company Master', 'ApplicationRole', 'Company Master', 'CompanyMaster', 4, 1, 'Index', 1, 'fa fa-building'),
(NEWID(), 'CompanyMasterCreate', 'Can Create Company Master', 'ApplicationRole', 'Company Master', 'CompanyMaster', 4, 1, 'Create', 1, 'fa fa-building'),
(NEWID(), 'CompanyMasterEdit', 'Can Edit Company Master', 'ApplicationRole', 'Company Master', 'CompanyMaster', 4, 1, 'Edit', 1, 'fa fa-building'),
(NEWID(), 'CompanyMasterDelete', 'Can Delete Company Master', 'ApplicationRole', 'Company Master', 'CompanyMaster', 4, 1, 'Delete', 1, 'fa fa-building');

-- =============================================
-- 2. DESIGNATION MASTER (Order: 2)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'DesginationMasterIndex', 'Can View Designation Master', 'ApplicationRole', 'Designation Master', 'DesginationMaster', 4, 2, 'Index', 1, 'fa fa-id-badge'),
(NEWID(), 'DesginationMasterCreate', 'Can Create Designation Master', 'ApplicationRole', 'Designation Master', 'DesginationMaster', 4, 2, 'Create', 1, 'fa fa-id-badge'),
(NEWID(), 'DesginationMasterEdit', 'Can Edit Designation Master', 'ApplicationRole', 'Designation Master', 'DesginationMaster', 4, 2, 'Edit', 1, 'fa fa-id-badge'),
(NEWID(), 'DesginationMasterDelete', 'Can Delete Designation Master', 'ApplicationRole', 'Designation Master', 'DesginationMaster', 4, 2, 'Delete', 1, 'fa fa-id-badge');

-- =============================================
-- 3. DEPARTMENT MASTER (Order: 3)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'DepartmentMasterIndex', 'Can View Department Master', 'ApplicationRole', 'Department Master', 'DepartmentMaster', 4, 3, 'Index', 1, 'fa fa-sitemap'),
(NEWID(), 'DepartmentMasterCreate', 'Can Create Department Master', 'ApplicationRole', 'Department Master', 'DepartmentMaster', 4, 3, 'Create', 1, 'fa fa-sitemap'),
(NEWID(), 'DepartmentMasterEdit', 'Can Edit Department Master', 'ApplicationRole', 'Department Master', 'DepartmentMaster', 4, 3, 'Edit', 1, 'fa fa-sitemap'),
(NEWID(), 'DepartmentMasterDelete', 'Can Delete Department Master', 'ApplicationRole', 'Department Master', 'DepartmentMaster', 4, 3, 'Delete', 1, 'fa fa-sitemap');

-- =============================================
-- 4. COST FACTOR MASTER (Order: 4)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'CostFactorMasterIndex', 'Can View Cost Factor Master', 'ApplicationRole', 'Cost Factor Master', 'CostFactorMaster', 4, 4, 'Index', 1, 'fa fa-calculator'),
(NEWID(), 'CostFactorMasterCreate', 'Can Create Cost Factor Master', 'ApplicationRole', 'Cost Factor Master', 'CostFactorMaster', 4, 4, 'Create', 1, 'fa fa-calculator'),
(NEWID(), 'CostFactorMasterEdit', 'Can Edit Cost Factor Master', 'ApplicationRole', 'Cost Factor Master', 'CostFactorMaster', 4, 4, 'Edit', 1, 'fa fa-calculator'),
(NEWID(), 'CostFactorMasterDelete', 'Can Delete Cost Factor Master', 'ApplicationRole', 'Cost Factor Master', 'CostFactorMaster', 4, 4, 'Delete', 1, 'fa fa-calculator');

-- =============================================
-- 5. HSN CODE MASTER (Order: 5)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'HSNCodeMasterIndex', 'Can View HSN Code Master', 'ApplicationRole', 'HSN Code Master', 'HSNCodeMaster', 4, 5, 'Index', 1, 'fa fa-barcode'),
(NEWID(), 'HSNCodeMasterCreate', 'Can Create HSN Code Master', 'ApplicationRole', 'HSN Code Master', 'HSNCodeMaster', 4, 5, 'Create', 1, 'fa fa-barcode'),
(NEWID(), 'HSNCodeMasterEdit', 'Can Edit HSN Code Master', 'ApplicationRole', 'HSN Code Master', 'HSNCodeMaster', 4, 5, 'Edit', 1, 'fa fa-barcode'),
(NEWID(), 'HSNCodeMasterDelete', 'Can Delete HSN Code Master', 'ApplicationRole', 'HSN Code Master', 'HSNCodeMaster', 4, 5, 'Delete', 1, 'fa fa-barcode');

-- =============================================
-- 6. CUSTOMER MASTER (Order: 6)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'CustomerMasterIndex', 'Can View Customer Master', 'ApplicationRole', 'Customer Master', 'CustomerMaster', 4, 6, 'Index', 1, 'fa-solid fa-person'),
(NEWID(), 'CustomerMasterCreate', 'Can Create Customer Master', 'ApplicationRole', 'Customer Master', 'CustomerMaster', 4, 6, 'Create', 1, 'fa-solid fa-person'),
(NEWID(), 'CustomerMasterEdit', 'Can Edit Customer Master', 'ApplicationRole', 'Customer Master', 'CustomerMaster', 4, 6, 'Edit', 1, 'fa-solid fa-person'),
(NEWID(), 'CustomerMasterDelete', 'Can Delete Customer Master', 'ApplicationRole', 'Customer Master', 'CustomerMaster', 4, 6, 'Delete', 1, 'fa-solid fa-person');

-- =============================================
-- 7. SUPPLIER MASTER (Order: 7)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'SupplierMasterIndex', 'Can View Supplier Master', 'ApplicationRole', 'Supplier Master', 'SupplierMaster', 4, 7, 'Index', 1, 'fa fa-truck'),
(NEWID(), 'SupplierMasterCreate', 'Can Create Supplier Master', 'ApplicationRole', 'Supplier Master', 'SupplierMaster', 4, 7, 'Create', 1, 'fa fa-truck'),
(NEWID(), 'SupplierMasterEdit', 'Can Edit Supplier Master', 'ApplicationRole', 'Supplier Master', 'SupplierMaster', 4, 7, 'Edit', 1, 'fa fa-truck'),
(NEWID(), 'SupplierMasterDelete', 'Can Delete Supplier Master', 'ApplicationRole', 'Supplier Master', 'SupplierMaster', 4, 7, 'Delete', 1, 'fa fa-truck');

-- =============================================
-- 8. LOCATION MASTER (Order: 8)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'LocationMasterIndex', 'Can View Location Master', 'ApplicationRole', 'Location Master', 'LocationMaster', 4, 8, 'Index', 1, 'fa-solid fa-map-location-dot'),
(NEWID(), 'LocationMasterCreate', 'Can Create Location Master', 'ApplicationRole', 'Location Master', 'LocationMaster', 4, 8, 'Create', 1, 'fa-solid fa-map-location-dot'),
(NEWID(), 'LocationMasterEdit', 'Can Edit Location Master', 'ApplicationRole', 'Location Master', 'LocationMaster', 4, 8, 'Edit', 1, 'fa-solid fa-map-location-dot'),
(NEWID(), 'LocationMasterDelete', 'Can Delete Location Master', 'ApplicationRole', 'Location Master', 'LocationMaster', 4, 8, 'Delete', 1, 'fa-solid fa-map-location-dot');

-- =============================================
-- 9. STATE MASTER (Order: 9)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'StateMasterIndex', 'Can View State Master', 'ApplicationRole', 'State Master', 'StateMaster', 4, 9, 'Index', 1, 'fa-solid fa-compass'),
(NEWID(), 'StateMasterCreate', 'Can Create State Master', 'ApplicationRole', 'State Master', 'StateMaster', 4, 9, 'Create', 1, 'fa-solid fa-compass'),
(NEWID(), 'StateMasterEdit', 'Can Edit State Master', 'ApplicationRole', 'State Master', 'StateMaster', 4, 9, 'Edit', 1, 'fa-solid fa-compass'),
(NEWID(), 'StateMasterDelete', 'Can Delete State Master', 'ApplicationRole', 'State Master', 'StateMaster', 4, 9, 'Delete', 1, 'fa-solid fa-compass');

-- =============================================
-- 10. UNIT MASTER (Order: 10)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'UnitMasterIndex', 'Can View Unit Master', 'ApplicationRole', 'Unit Master', 'UnitMaster', 4, 10, 'Index', 1, 'fa fa-balance-scale'),
(NEWID(), 'UnitMasterCreate', 'Can Create Unit Master', 'ApplicationRole', 'Unit Master', 'UnitMaster', 4, 10, 'Create', 1, 'fa fa-balance-scale'),
(NEWID(), 'UnitMasterEdit', 'Can Edit Unit Master', 'ApplicationRole', 'Unit Master', 'UnitMaster', 4, 10, 'Edit', 1, 'fa fa-balance-scale'),
(NEWID(), 'UnitMasterDelete', 'Can Delete Unit Master', 'ApplicationRole', 'Unit Master', 'UnitMaster', 4, 10, 'Delete', 1, 'fa fa-balance-scale');

-- =============================================
-- 11. MATERIAL MASTER (Order: 11)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'MaterialMasterIndex', 'Can View Material Master', 'ApplicationRole', 'Material Master', 'MaterialMaster', 4, 11, 'Index', 1, 'fa-solid fa-atom'),
(NEWID(), 'MaterialMasterCreate', 'Can Create Material Master', 'ApplicationRole', 'Material Master', 'MaterialMaster', 4, 11, 'Create', 1, 'fa-solid fa-atom'),
(NEWID(), 'MaterialMasterEdit', 'Can Edit Material Master', 'ApplicationRole', 'Material Master', 'MaterialMaster', 4, 11, 'Edit', 1, 'fa-solid fa-atom'),
(NEWID(), 'MaterialMasterDelete', 'Can Delete Material Master', 'ApplicationRole', 'Material Master', 'MaterialMaster', 4, 11, 'Delete', 1, 'fa-solid fa-atom');

-- =============================================
-- 12. MATERIAL TYPE MASTER (Order: 12)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'MaterialTypeMasterIndex', 'Can View Material Type Master', 'ApplicationRole', 'Material Type Master', 'MaterialTypeMaster', 4, 12, 'Index', 1, 'fa fa-cubes'),
(NEWID(), 'MaterialTypeMasterCreate', 'Can Create Material Type Master', 'ApplicationRole', 'Material Type Master', 'MaterialTypeMaster', 4, 12, 'Create', 1, 'fa fa-cubes'),
(NEWID(), 'MaterialTypeMasterEdit', 'Can Edit Material Type Master', 'ApplicationRole', 'Material Type Master', 'MaterialTypeMaster', 4, 12, 'Edit', 1, 'fa fa-cubes'),
(NEWID(), 'MaterialTypeMasterDelete', 'Can Delete Material Type Master', 'ApplicationRole', 'Material Type Master', 'MaterialTypeMaster', 4, 12, 'Delete', 1, 'fa fa-cubes');

-- =============================================
-- 13. MATERIAL GROUP MASTER (Order: 13)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'MaterialGroupMasterIndex', 'Can View Material Group Master', 'ApplicationRole', 'Material Group Master', 'MaterialGroupMaster', 4, 13, 'Index', 1, 'fa fa-layer-group'),
(NEWID(), 'MaterialGroupMasterCreate', 'Can Create Material Group Master', 'ApplicationRole', 'Material Group Master', 'MaterialGroupMaster', 4, 13, 'Create', 1, 'fa fa-layer-group'),
(NEWID(), 'MaterialGroupMasterEdit', 'Can Edit Material Group Master', 'ApplicationRole', 'Material Group Master', 'MaterialGroupMaster', 4, 13, 'Edit', 1, 'fa fa-layer-group'),
(NEWID(), 'MaterialGroupMasterDelete', 'Can Delete Material Group Master', 'ApplicationRole', 'Material Group Master', 'MaterialGroupMaster', 4, 13, 'Delete', 1, 'fa fa-layer-group');

-- =============================================
-- 14. PACKING MASTER (Order: 14)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'PackingMasterIndex', 'Can View Packing Master', 'ApplicationRole', 'Packing Master', 'PackingMaster', 4, 14, 'Index', 1, 'fa fa-box'),
(NEWID(), 'PackingMasterCreate', 'Can Create Packing Master', 'ApplicationRole', 'Packing Master', 'PackingMaster', 4, 14, 'Create', 1, 'fa fa-box'),
(NEWID(), 'PackingMasterEdit', 'Can Edit Packing Master', 'ApplicationRole', 'Packing Master', 'PackingMaster', 4, 14, 'Edit', 1, 'fa fa-box'),
(NEWID(), 'PackingMasterDelete', 'Can Delete Packing Master', 'ApplicationRole', 'Packing Master', 'PackingMaster', 4, 14, 'Delete', 1, 'fa fa-box');

-- =============================================
-- 15. PACKING TYPE MASTER (Order: 15)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'PackingTypeMasterIndex', 'Can View Packing Type Master', 'ApplicationRole', 'Packing Type Master', 'PackingTypeMaster', 4, 15, 'Index', 1, 'fa fa-cube'),
(NEWID(), 'PackingTypeMasterCreate', 'Can Create Packing Type Master', 'ApplicationRole', 'Packing Type Master', 'PackingTypeMaster', 4, 15, 'Create', 1, 'fa fa-cube'),
(NEWID(), 'PackingTypeMasterEdit', 'Can Edit Packing Type Master', 'ApplicationRole', 'Packing Type Master', 'PackingTypeMaster', 4, 15, 'Edit', 1, 'fa fa-cube'),
(NEWID(), 'PackingTypeMasterDelete', 'Can Delete Packing Type Master', 'ApplicationRole', 'Packing Type Master', 'PackingTypeMaster', 4, 15, 'Delete', 1, 'fa fa-cube');

-- =============================================
-- 16. LABORATORY MASTER (Order: 16)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'LaboratoryMasterIndex', 'Can View Laboratory Master', 'ApplicationRole', 'Laboratory Master', 'LaboratoryMaster', 4, 16, 'Index', 1, 'fa fa-flask'),
(NEWID(), 'LaboratoryMasterCreate', 'Can Create Laboratory Master', 'ApplicationRole', 'Laboratory Master', 'LaboratoryMaster', 4, 16, 'Create', 1, 'fa fa-flask'),
(NEWID(), 'LaboratoryMasterEdit', 'Can Edit Laboratory Master', 'ApplicationRole', 'Laboratory Master', 'LaboratoryMaster', 4, 16, 'Edit', 1, 'fa fa-flask'),
(NEWID(), 'LaboratoryMasterDelete', 'Can Delete Laboratory Master', 'ApplicationRole', 'Laboratory Master', 'LaboratoryMaster', 4, 16, 'Delete', 1, 'fa fa-flask');

-- =============================================
-- VERIFICATION QUERY
-- Run this to verify all 64 roles were inserted
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
WHERE RMenuGroupId = 4
ORDER BY RMenuGroupOrder, 
    CASE RMenuIndex 
        WHEN 'Index' THEN 1 
        WHEN 'Create' THEN 2 
        WHEN 'Edit' THEN 3 
        WHEN 'Delete' THEN 4 
    END;

-- Expected Result: 64 rows (16 masters × 4 actions each)
