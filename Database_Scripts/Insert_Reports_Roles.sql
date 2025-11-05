-- =============================================
-- Insert Roles for Reports Menu in KVM_ERP
-- RMenuGroupId = 3 (Reports Menu)
-- Each Report has 4 actions: Index, Create, Edit, Delete
-- Total: 4 Records (1 Report × 4 Actions)
-- =============================================

-- Clear existing Reports roles if needed (OPTIONAL - COMMENT OUT IF NOT NEEDED)
-- DELETE FROM AspNetRoles WHERE RMenuGroupId = 3;

-- =============================================
-- 1. RAW MATERIALS IMPORT REPORT (Order: 1)
-- =============================================
INSERT INTO AspNetRoles (Id, Name, Description, Discriminator, RMenuType, RControllerName, RMenuGroupId, RMenuGroupOrder, RMenuIndex, SDPTID, RImageClassName)
VALUES 
(NEWID(), 'RawMaterialsImportReportIndex', 'Can View Raw Materials Import Report', 'ApplicationRole', 'Raw Materials Import Report', 'Reports', 3, 1, 'Index', 1, 'fa fa-file-excel'),
(NEWID(), 'RawMaterialsImportReportCreate', 'Can Create Raw Materials Import Report', 'ApplicationRole', 'Raw Materials Import Report', 'Reports', 3, 1, 'Create', 1, 'fa fa-file-excel'),
(NEWID(), 'RawMaterialsImportReportEdit', 'Can Edit Raw Materials Import Report', 'ApplicationRole', 'Raw Materials Import Report', 'Reports', 3, 1, 'Edit', 1, 'fa fa-file-excel'),
(NEWID(), 'RawMaterialsImportReportDelete', 'Can Delete Raw Materials Import Report', 'ApplicationRole', 'Raw Materials Import Report', 'Reports', 3, 1, 'Delete', 1, 'fa fa-file-excel');

-- =============================================
-- VERIFICATION QUERY
-- Run this to verify all 4 roles were inserted
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
WHERE RMenuGroupId = 3
ORDER BY RMenuGroupOrder, 
    CASE RMenuIndex 
        WHEN 'Index' THEN 1 
        WHEN 'Create' THEN 2 
        WHEN 'Edit' THEN 3 
        WHEN 'Delete' THEN 4 
    END;

-- Expected Result: 4 rows (1 report × 4 actions)

-- =============================================
-- REPORTS MENU STRUCTURE SUMMARY
-- =============================================
/*
Reports Menu (RMenuGroupId = 3):
┌─────┬──────────────────────────────┬─────────────────────┬───────┬────────────────────┐
│ Ord │ Report Name                  │ Controller          │ Order │ Icon               │
├─────┼──────────────────────────────┼─────────────────────┼───────┼────────────────────┤
│  1  │ Raw Materials Import Report  │ Reports             │   1   │ fa fa-file-excel   │
└─────┴──────────────────────────────┴─────────────────────┴───────┴────────────────────┘

Each Report has 4 permissions:
- Index  (View)
- Create (Generate New)
- Edit   (Modify)
- Delete (Remove)

Total: 4 role records for Reports menu
*/
